// Package api is the mqtt-admin HTTP surface. Every route is explicit and guarded by
// exactly one delegated scope; there is no generic passthrough to the broker. The API
// administers clients (users) and the roles that grant them access, behind guardrails: the
// broker's own roles are reserved, nothing may be granted the control channel, and every
// change is audited.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/auth"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/docs"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/dynsec"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/scopes"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/stats"
)

const (
	ScopeClientsRead       = scopes.ClientsRead
	ScopeClientsWrite      = scopes.ClientsWrite
	ScopeClientsDelete     = scopes.ClientsDelete
	ScopeCredentialsRotate = scopes.CredentialsRotate
	ScopeRolesRead         = scopes.RolesRead
	ScopeRolesWrite        = scopes.RolesWrite
	ScopeRolesDelete       = scopes.RolesDelete
	ScopeServerRead        = scopes.ServerRead

	minPassword  = 24
	maxPassword  = 128
	maxBodyBytes = 32 << 10
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// StatsSource provides the latest broker statistics snapshot.
type StatsSource interface{ Snapshot() stats.Snapshot }

type Options struct {
	Broker dynsec.Broker
	Stats  StatsSource
	Auth   auth.Authorizer
	// AllowedRoles optionally restricts which roles may be assigned to clients. Empty means
	// every role that is not reserved.
	AllowedRoles []string
	// ReservedRoles can never be created, edited, deleted or assigned through the API.
	// Nil means the broker's own roles: admin and dynsec-admin.
	ReservedRoles []string
	// DefaultRole is given to a new client when the caller names no role.
	DefaultRole    string
	ProtectedUsers []string
	// AuthFailureLimit is how many 401/403 responses one client address may cause per
	// minute before it is answered 429. Zero disables the limit.
	AuthFailureLimit int
	// Docs fills the deployment-specific values of the served documentation.
	Docs docs.Vars
}

type server struct {
	broker      dynsec.Broker
	stats       StatsSource
	allowOnly   []string
	reserved    map[string]bool
	defaultRole string
	protected   map[string]bool
	docs        docs.Vars
}

func New(opts Options) http.Handler {
	s := &server{
		broker: opts.Broker, stats: opts.Stats, allowOnly: opts.AllowedRoles,
		defaultRole: opts.DefaultRole, docs: opts.Docs, protected: map[string]bool{}, reserved: map[string]bool{},
	}
	for _, u := range opts.ProtectedUsers {
		s.protected[u] = true
	}
	reserved := opts.ReservedRoles
	if reserved == nil {
		reserved = []string{"admin", "dynsec-admin"}
	}
	for _, role := range reserved {
		s.reserved[role] = true
	}
	a := opts.Auth
	mux := http.NewServeMux()

	// Health reflects the broker connection: 200 while connected, 503 while it is down.
	// The body is deliberately minimal because this route is public.
	health := func(w http.ResponseWriter, _ *http.Request) {
		if !s.broker.Connected() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("GET /ready", health) // kept as an alias

	mux.Handle("GET /admin/api/server", a.Require(ScopeServerRead, http.HandlerFunc(s.serverStatus)))
	mux.Handle("GET /admin/api/docs", a.Require(ScopeServerRead, http.HandlerFunc(listDocs)))
	mux.Handle("GET /admin/api/docs/{version}", a.Require(ScopeServerRead, http.HandlerFunc(s.getDoc)))
	mux.Handle("GET /admin/api/stats", a.Require(ScopeServerRead, http.HandlerFunc(s.brokerStats)))
	mux.Handle("GET /admin/api/roles", a.Require(ScopeRolesRead, http.HandlerFunc(s.listRoles)))
	mux.Handle("POST /admin/api/roles", a.Require(ScopeRolesWrite, http.HandlerFunc(s.createRole)))
	mux.Handle("GET /admin/api/roles/{name}", a.Require(ScopeRolesRead, http.HandlerFunc(s.getRole)))
	mux.Handle("DELETE /admin/api/roles/{name}", a.Require(ScopeRolesDelete, http.HandlerFunc(s.deleteRole)))
	mux.Handle("POST /admin/api/roles/{name}/acls", a.Require(ScopeRolesWrite, http.HandlerFunc(s.addACL)))
	mux.Handle("POST /admin/api/roles/{name}/acls/remove", a.Require(ScopeRolesWrite, http.HandlerFunc(s.removeACL)))
	mux.Handle("PUT /admin/api/clients/{username}/roles/{role}", a.Require(ScopeRolesWrite, http.HandlerFunc(s.assignRole)))
	mux.Handle("DELETE /admin/api/clients/{username}/roles/{role}", a.Require(ScopeRolesWrite, http.HandlerFunc(s.unassignRole)))
	mux.Handle("GET /admin/api/clients", a.Require(ScopeClientsRead, http.HandlerFunc(s.listClients)))
	mux.Handle("GET /admin/api/clients/{username}", a.Require(ScopeClientsRead, http.HandlerFunc(s.getClient)))
	mux.Handle("POST /admin/api/clients", a.Require(ScopeClientsWrite, http.HandlerFunc(s.createClient)))
	mux.Handle("POST /admin/api/clients/{username}/disable", a.Require(ScopeClientsWrite, s.setDisabled(true)))
	mux.Handle("POST /admin/api/clients/{username}/enable", a.Require(ScopeClientsWrite, s.setDisabled(false)))
	mux.Handle("POST /admin/api/clients/{username}/password", a.Require(ScopeCredentialsRotate, http.HandlerFunc(s.rotatePassword)))
	mux.Handle("DELETE /admin/api/clients/{username}", a.Require(ScopeClientsDelete, http.HandlerFunc(s.deleteClient)))

	return secure(newFailureLimiter(opts.AuthFailureLimit, time.Minute).middleware(mux))
}

// ---- DTOs ----

type clientDTO struct {
	Username string   `json:"username"`
	Disabled bool     `json:"disabled"`
	Roles    []string `json:"roles"`
}

type dynClient struct {
	Username string `json:"username"`
	Disabled bool   `json:"disabled"`
	Roles    []struct {
		RoleName string `json:"rolename"`
	} `json:"roles"`
}

func (c dynClient) dto() clientDTO {
	out := clientDTO{Username: c.Username, Disabled: c.Disabled, Roles: []string{}}
	for _, r := range c.Roles {
		// An empty name is a dangling reference left by the broker, not a real role.
		if r.RoleName != "" {
			out.Roles = append(out.Roles, r.RoleName)
		}
	}
	return out
}

// ---- handlers ----

func (s *server) listClients(w http.ResponseWriter, r *http.Request) {
	data, err := s.broker.Do(r.Context(), map[string]any{"command": "listClients", "verbose": true})
	if err != nil {
		s.fail(w, r, "list_clients", "", err)
		return
	}
	var payload struct {
		Clients []dynClient `json:"clients"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		s.fail(w, r, "list_clients", "", errBadBrokerReply)
		return
	}
	out := make([]clientDTO, 0, len(payload.Clients))
	for _, c := range payload.Clients {
		out = append(out, c.dto())
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *server) getClient(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if !validUsername(w, username) {
		return
	}
	data, err := s.broker.Do(r.Context(), map[string]any{"command": "getClient", "username": username})
	if err != nil {
		s.fail(w, r, "get_client", username, err)
		return
	}
	var payload struct {
		Client dynClient `json:"client"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		s.fail(w, r, "get_client", username, errBadBrokerReply)
		return
	}
	writeJSON(w, http.StatusOK, payload.Client.dto())
}

type createRequest struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

func (s *server) createClient(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decode(w, r, &req) || !validUsername(w, req.Username) {
		return
	}
	if s.protected[req.Username] {
		writeError(w, http.StatusForbidden, "protected_user")
		return
	}
	role := req.Role
	if role == "" {
		var err error
		if role, err = s.defaultRoleFor(r.Context()); errors.Is(err, errRoleRequired) {
			writeError(w, http.StatusBadRequest, "role_required")
			return
		} else if err != nil {
			s.fail(w, r, "create_client", req.Username, err)
			return
		}
	}
	if !validRoleName(w, role) {
		return
	}
	if !s.isAssignable(role) {
		writeError(w, http.StatusBadRequest, "role_not_allowed")
		return
	}
	password, generated, ok := resolvePassword(w, req.Password)
	if !ok {
		return
	}
	// The role is attached with a separate addClientRole, never inside createClient.
	// Mosquitto 2.1.2 links a role given inline to the client in a way deleteRole does not
	// undo: the client keeps a dangling reference to the freed role, which corrupts
	// memory and has crashed the broker. addClientRole links both sides correctly.
	if _, err := s.broker.Do(r.Context(), map[string]any{
		"command":  "createClient",
		"username": req.Username,
		"password": password,
	}); err != nil {
		s.fail(w, r, "create_client", req.Username, err)
		return
	}
	if _, err := s.broker.Do(r.Context(), map[string]any{
		"command": "addClientRole", "username": req.Username, "rolename": role,
	}); err != nil {
		s.rollbackClient(r, req.Username)
		s.fail(w, r, "create_client", req.Username, err)
		return
	}
	audit(r, "create_client", req.Username, "ok role="+role)
	resp := map[string]any{"username": req.Username, "role": role}
	if generated {
		resp["password"] = password // returned exactly once; never logged
	}
	noStore(w)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *server) setDisabled(disable bool) http.Handler {
	command, action := "enableClient", "enable_client"
	if disable {
		command, action = "disableClient", "disable_client"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		if !validUsername(w, username) || s.rejectProtected(w, username) {
			return
		}
		if _, err := s.broker.Do(r.Context(), map[string]any{"command": command, "username": username}); err != nil {
			s.fail(w, r, action, username, err)
			return
		}
		audit(r, action, username, "ok")
		w.WriteHeader(http.StatusNoContent)
	})
}

type passwordRequest struct {
	Password string `json:"password"`
}

func (s *server) rotatePassword(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if !validUsername(w, username) || s.rejectProtected(w, username) {
		return
	}
	var req passwordRequest
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	password, generated, ok := resolvePassword(w, req.Password)
	if !ok {
		return
	}
	if _, err := s.broker.Do(r.Context(), map[string]any{"command": "setClientPassword", "username": username, "password": password}); err != nil {
		s.fail(w, r, "rotate_password", username, err)
		return
	}
	audit(r, "rotate_password", username, "ok")
	if !generated {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, map[string]any{"username": username, "password": password})
}

func (s *server) deleteClient(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if !validUsername(w, username) || s.rejectProtected(w, username) {
		return
	}
	if _, err := s.broker.Do(r.Context(), map[string]any{"command": "deleteClient", "username": username}); err != nil {
		s.fail(w, r, "delete_client", username, err)
		return
	}
	audit(r, "delete_client", username, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// listDocs and getDoc serve the embedded documentation. The control plane passes the
// UI language as ?lang=; anything unrecognised is answered in English.
func listDocs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"versions": docs.Versions()})
}

func (s *server) getDoc(w http.ResponseWriter, r *http.Request) {
	doc, ok := docs.Get(r.PathValue("version"), r.URL.Query().Get("lang"), s.docs)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *server) brokerStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.stats.Snapshot())
}

func (s *server) serverStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{"brokerConnected": s.broker.Connected()}
	if data, err := s.broker.Do(r.Context(), map[string]any{"command": "listClients", "count": 1}); err == nil {
		var payload struct {
			TotalCount int `json:"totalCount"`
		}
		if json.Unmarshal(data, &payload) == nil {
			status["clients"] = payload.TotalCount
		}
		status["dynsecReachable"] = true
	} else {
		status["dynsecReachable"] = false
	}
	writeJSON(w, http.StatusOK, status)
}

// ---- helpers ----

var errBadBrokerReply = errors.New("unexpected broker reply")

func (s *server) rejectProtected(w http.ResponseWriter, username string) bool {
	if s.protected[username] {
		writeError(w, http.StatusForbidden, "protected_user")
		return true
	}
	return false
}

// fail maps a broker error to an HTTP status without leaking broker internals.
func (s *server) fail(w http.ResponseWriter, r *http.Request, action, target string, err error) {
	var dyn *dynsec.Error
	switch {
	case errors.As(err, &dyn):
		msg := strings.ToLower(dyn.Message)
		switch {
		case strings.Contains(msg, "not found"):
			writeError(w, http.StatusNotFound, "not_found")
		case strings.Contains(msg, "already exists"):
			writeError(w, http.StatusConflict, "already_exists")
		default:
			writeError(w, http.StatusBadRequest, "rejected_by_broker")
		}
		audit(r, action, target, "rejected: "+dyn.Message)
	case errors.Is(err, dynsec.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "broker_unavailable")
		audit(r, action, target, "broker unavailable")
	default:
		writeError(w, http.StatusBadGateway, "broker_error")
		audit(r, action, target, "broker error")
	}
}

func validUsername(w http.ResponseWriter, username string) bool {
	if !usernameRE.MatchString(username) {
		writeError(w, http.StatusBadRequest, "invalid_username")
		return false
	}
	return true
}

// resolvePassword returns the caller's password after validation, or a freshly generated
// one. The bool reports whether it was generated (and must therefore be shown once).
func resolvePassword(w http.ResponseWriter, supplied string) (string, bool, bool) {
	if supplied == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error")
			return "", false, false
		}
		return base64.RawURLEncoding.EncodeToString(raw), true, true
	}
	if len(supplied) < minPassword || len(supplied) > maxPassword || strings.ContainsFunc(supplied, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		writeError(w, http.StatusBadRequest, "invalid_password")
		return "", false, false
	}
	return supplied, false, true
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return false
	}
	return true
}

func audit(r *http.Request, action, target, result string) {
	actor := "unknown"
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		actor = p.Subject
	}
	slog.InfoContext(r.Context(), "audit", "actor", actor, "action", action, "target", target, "result", result, "request_id", w3id(r))
}

func w3id(r *http.Request) string { return r.Header.Get("X-Request-Id") }

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// secure adds response headers and bounds request time.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
