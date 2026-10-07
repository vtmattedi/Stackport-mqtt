package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/dynsec"
)

var errRoleRequired = errors.New("a role is required")

// ---- broker shapes and DTOs ----

type dynACL struct {
	ACLType  string `json:"acltype"`
	Topic    string `json:"topic"`
	Allow    bool   `json:"allow"`
	Priority int    `json:"priority"`
}

type dynRole struct {
	RoleName        string   `json:"rolename"`
	TextDescription string   `json:"textdescription"`
	ACLs            []dynACL `json:"acls"`
}

type aclDTO struct {
	Type     string `json:"type"`
	Topic    string `json:"topic"`
	Allow    bool   `json:"allow"`
	Priority int    `json:"priority"`
}

type roleDTO struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	ACLs        []aclDTO `json:"acls"`
	// Reserved roles belong to the broker's own administration and can never be edited,
	// deleted or assigned through this API.
	Reserved bool `json:"reserved"`
	// Assignable roles may be given to clients through this API.
	Assignable  bool     `json:"assignable"`
	ClientCount int      `json:"clientCount"`
	Clients     []string `json:"clients,omitempty"`
}

func (s *server) roleDTO(r dynRole, members []string, withClients bool) roleDTO {
	out := roleDTO{
		Name:        r.RoleName,
		Description: r.TextDescription,
		ACLs:        []aclDTO{},
		Reserved:    s.reserved[r.RoleName],
		Assignable:  s.isAssignable(r.RoleName),
		ClientCount: len(members),
	}
	for _, a := range r.ACLs {
		out.ACLs = append(out.ACLs, aclDTO{Type: a.ACLType, Topic: a.Topic, Allow: a.Allow, Priority: a.Priority})
	}
	if withClients {
		out.Clients = append([]string{}, members...)
	}
	return out
}

// isAssignable reports whether the API may give this role to a client: never a reserved
// role, and, when MQTT_ALLOWED_ROLES is set, only the roles it lists.
func (s *server) isAssignable(role string) bool {
	if s.reserved[role] {
		return false
	}
	return len(s.allowOnly) == 0 || contains(s.allowOnly, role)
}

// clientsByRole maps each role name to the clients that hold it.
func (s *server) clientsByRole(ctx context.Context) (map[string][]string, error) {
	data, err := s.broker.Do(ctx, map[string]any{"command": "listClients", "verbose": true})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Clients []dynClient `json:"clients"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, errBadBrokerReply
	}
	out := map[string][]string{}
	for _, c := range payload.Clients {
		for _, role := range c.Roles {
			out[role.RoleName] = append(out[role.RoleName], c.Username)
		}
	}
	for role := range out {
		sort.Strings(out[role])
	}
	return out, nil
}

func (s *server) fetchRoles(ctx context.Context) ([]dynRole, error) {
	data, err := s.broker.Do(ctx, map[string]any{"command": "listRoles", "verbose": true})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Roles []dynRole `json:"roles"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, errBadBrokerReply
	}
	return payload.Roles, nil
}

// defaultRoleFor picks the role for a new client when the caller names none: the configured
// default, the only allowed role, or the only assignable role that exists. Otherwise the
// caller must say which role it wants.
func (s *server) defaultRoleFor(ctx context.Context) (string, error) {
	if s.defaultRole != "" {
		return s.defaultRole, nil
	}
	if len(s.allowOnly) == 1 && !s.reserved[s.allowOnly[0]] {
		return s.allowOnly[0], nil
	}
	roles, err := s.fetchRoles(ctx)
	if err != nil {
		return "", err
	}
	var candidates []string
	for _, r := range roles {
		if s.isAssignable(r.RoleName) {
			candidates = append(candidates, r.RoleName)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	return "", errRoleRequired
}

// ---- role handlers ----

func (s *server) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.fetchRoles(r.Context())
	if err != nil {
		s.fail(w, r, "list_roles", "", err)
		return
	}
	members, err := s.clientsByRole(r.Context())
	if err != nil {
		s.fail(w, r, "list_roles", "", err)
		return
	}
	out := make([]roleDTO, 0, len(roles))
	assignable := []string{}
	for _, role := range roles {
		out = append(out, s.roleDTO(role, members[role.RoleName], false))
		if s.isAssignable(role.RoleName) {
			assignable = append(assignable, role.RoleName)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out, "assignable": assignable})
}

func (s *server) getRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validRoleName(w, name) {
		return
	}
	data, err := s.broker.Do(r.Context(), map[string]any{"command": "getRole", "rolename": name})
	if err != nil {
		s.fail(w, r, "get_role", name, err)
		return
	}
	var payload struct {
		Role dynRole `json:"role"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		s.fail(w, r, "get_role", name, errBadBrokerReply)
		return
	}
	if payload.Role.RoleName == "" {
		payload.Role.RoleName = name
	}
	members, err := s.clientsByRole(r.Context())
	if err != nil {
		s.fail(w, r, "get_role", name, err)
		return
	}
	writeJSON(w, http.StatusOK, s.roleDTO(payload.Role, members[name], true))
}

type createRoleRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ACLs        []ACLInput `json:"acls"`
}

// createRole creates a role and its first ACLs together. Everything is validated before the
// broker is touched, and if an ACL cannot be added the role is removed again, so a failure
// never leaves a half-configured role that clients could be given.
func (s *server) createRole(w http.ResponseWriter, r *http.Request) {
	var req createRoleRequest
	if !decode(w, r, &req) || !validRoleName(w, req.Name) || s.rejectReserved(w, req.Name) {
		return
	}
	if !validDescription(req.Description) {
		writeError(w, http.StatusBadRequest, "invalid_description")
		return
	}
	if len(req.ACLs) > maxACLsPerCreate {
		writeError(w, http.StatusBadRequest, "invalid_acl")
		return
	}
	for _, a := range req.ACLs {
		if code := validateACL(a); code != "" {
			status := http.StatusBadRequest
			if code == "forbidden_topic" {
				status = http.StatusForbidden
			}
			writeError(w, status, code)
			return
		}
	}

	command := map[string]any{"command": "createRole", "rolename": req.Name}
	if req.Description != "" {
		command["textdescription"] = req.Description
	}
	if _, err := s.broker.Do(r.Context(), command); err != nil {
		s.fail(w, r, "create_role", req.Name, err)
		return
	}
	for _, a := range req.ACLs {
		if _, err := s.broker.Do(r.Context(), addACLCommand(req.Name, a)); err != nil {
			s.rollbackRole(r, req.Name)
			s.fail(w, r, "create_role", req.Name, err)
			return
		}
	}
	audit(r, "create_role", req.Name, "ok acls="+itoa(len(req.ACLs)))
	writeJSON(w, http.StatusCreated, map[string]any{"name": req.Name, "acls": len(req.ACLs)})
}

func (s *server) rollbackRole(r *http.Request, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.broker.Do(ctx, map[string]any{"command": "deleteRole", "rolename": name}); err != nil {
		audit(r, "create_role", name, "rollback failed: "+err.Error())
		return
	}
	audit(r, "create_role", name, "rolled back")
}

func (s *server) rollbackClient(r *http.Request, username string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.broker.Do(ctx, map[string]any{"command": "deleteClient", "username": username}); err != nil {
		audit(r, "create_client", username, "rollback failed: "+err.Error())
		return
	}
	audit(r, "create_client", username, "rolled back")
}

// deleteRole refuses to remove a role that clients still hold unless the caller says
// ?force=true, because deleting it silently strips those clients of their access.
func (s *server) deleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validRoleName(w, name) || s.rejectReserved(w, name) {
		return
	}
	members, err := s.clientsByRole(r.Context())
	if err != nil {
		s.fail(w, r, "delete_role", name, err)
		return
	}
	if n := len(members[name]); n > 0 && r.URL.Query().Get("force") != "true" {
		audit(r, "delete_role", name, "refused: role in use by "+itoa(n)+" clients")
		writeJSON(w, http.StatusConflict, map[string]any{"error": "role_in_use", "clients": n})
		return
	}
	// Unlink every member before deleting. Deleting a role that is still linked to a client
	// leaves that client with a dangling reference in Mosquitto 2.1.2 (it was created with
	// the role inline, as older versions of this service did), which corrupts memory and has
	// crashed the broker. Removing the role from each client first is always clean.
	for _, username := range members[name] {
		if _, err := s.broker.Do(r.Context(), map[string]any{
			"command": "removeClientRole", "username": username, "rolename": name,
		}); err != nil {
			s.fail(w, r, "delete_role", name, err)
			return
		}
	}
	if _, err := s.broker.Do(r.Context(), map[string]any{"command": "deleteRole", "rolename": name}); err != nil {
		s.fail(w, r, "delete_role", name, err)
		return
	}
	audit(r, "delete_role", name, "ok clients_affected="+itoa(len(members[name])))
	w.WriteHeader(http.StatusNoContent)
}

func addACLCommand(role string, a ACLInput) map[string]any {
	return map[string]any{
		"command":  "addRoleACL",
		"rolename": role,
		"acltype":  a.Type,
		"topic":    a.Topic,
		"priority": a.priority(),
		"allow":    a.allow(),
	}
}

func (s *server) addACL(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validRoleName(w, name) || s.rejectReserved(w, name) {
		return
	}
	var a ACLInput
	if !decode(w, r, &a) {
		return
	}
	if code := validateACL(a); code != "" {
		status := http.StatusBadRequest
		if code == "forbidden_topic" {
			status = http.StatusForbidden
		}
		audit(r, "add_role_acl", name, "refused "+code+" "+a.Type+" "+a.Topic)
		writeError(w, status, code)
		return
	}
	if _, err := s.broker.Do(r.Context(), addACLCommand(name, a)); err != nil {
		s.fail(w, r, "add_role_acl", name, err)
		return
	}
	audit(r, "add_role_acl", name, "ok "+a.Type+" "+a.Topic)
	writeJSON(w, http.StatusCreated, aclDTO{Type: a.Type, Topic: a.Topic, Allow: a.allow(), Priority: a.priority()})
}

type removeACLRequest struct {
	Type  string `json:"type"`
	Topic string `json:"topic"`
}

// removeACL is a POST with a body rather than a DELETE: topic filters contain '/', '+' and
// '#', which do not belong in a path, and many proxies drop DELETE bodies.
func (s *server) removeACL(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validRoleName(w, name) || s.rejectReserved(w, name) {
		return
	}
	var req removeACLRequest
	if !decode(w, r, &req) {
		return
	}
	if !aclTypes[req.Type] || !validFilter(req.Topic) {
		writeError(w, http.StatusBadRequest, "invalid_acl")
		return
	}
	if _, err := s.broker.Do(r.Context(), map[string]any{
		"command": "removeRoleACL", "rolename": name, "acltype": req.Type, "topic": req.Topic,
	}); err != nil {
		s.fail(w, r, "remove_role_acl", name, err)
		return
	}
	audit(r, "remove_role_acl", name, "ok "+req.Type+" "+req.Topic)
	w.WriteHeader(http.StatusNoContent)
}

// ---- assigning roles to clients ----

func (s *server) assignRole(w http.ResponseWriter, r *http.Request) {
	username, role := r.PathValue("username"), r.PathValue("role")
	if !s.checkRoleChange(w, username, role) {
		return
	}
	if _, err := s.broker.Do(r.Context(), map[string]any{
		"command": "addClientRole", "username": username, "rolename": role,
	}); err != nil {
		// PUT is idempotent: a client that already holds the role is the state asked for.
		var dyn *dynsec.Error
		if errors.As(err, &dyn) && strings.Contains(strings.ToLower(dyn.Message), "already") {
			audit(r, "assign_role", username, "ok role="+role+" (already held)")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.fail(w, r, "assign_role", username, err)
		return
	}
	audit(r, "assign_role", username, "ok role="+role)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) unassignRole(w http.ResponseWriter, r *http.Request) {
	username, role := r.PathValue("username"), r.PathValue("role")
	if !s.checkRoleChange(w, username, role) {
		return
	}
	if _, err := s.broker.Do(r.Context(), map[string]any{
		"command": "removeClientRole", "username": username, "rolename": role,
	}); err != nil {
		s.fail(w, r, "unassign_role", username, err)
		return
	}
	audit(r, "unassign_role", username, "ok role="+role)
	w.WriteHeader(http.StatusNoContent)
}

// checkRoleChange applies the guardrails shared by assigning and removing a role.
func (s *server) checkRoleChange(w http.ResponseWriter, username, role string) bool {
	if !validUsername(w, username) || !validRoleName(w, role) || s.rejectProtected(w, username) {
		return false
	}
	if !s.isAssignable(role) {
		writeError(w, http.StatusBadRequest, "role_not_allowed")
		return false
	}
	return true
}

// ---- helpers ----

func validRoleName(w http.ResponseWriter, name string) bool {
	if !roleNameRE.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid_role")
		return false
	}
	return true
}

func (s *server) rejectReserved(w http.ResponseWriter, role string) bool {
	if s.reserved[role] {
		writeError(w, http.StatusForbidden, "reserved_role")
		return true
	}
	return false
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
