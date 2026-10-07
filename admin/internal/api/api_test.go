package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/dynsec"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/identity"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/stats"
)

type fakeIntrospector map[string]identity.Token

func (f fakeIntrospector) Introspect(_ context.Context, raw string) (identity.Token, error) {
	return f[raw], nil
}

type fakeBroker struct {
	mu       sync.Mutex
	commands []map[string]any
	reply    json.RawMessage
	err      error
	down     bool
	// fn, when set, answers each command individually (state-aware tests).
	fn func(cmd map[string]any) (json.RawMessage, error)
}

func (f *fakeBroker) Do(_ context.Context, c map[string]any) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, c)
	if f.fn != nil {
		return f.fn(c)
	}
	return f.reply, f.err
}
func (f *fakeBroker) Connected() bool { return !f.down }
func (f *fakeBroker) last() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.commands) == 0 {
		return nil
	}
	return f.commands[len(f.commands)-1]
}

const aud = "mw-mqtt"

type fakeStats struct{}

func (fakeStats) Snapshot() stats.Snapshot {
	return stats.Snapshot{Available: true, Version: "2.1.2", Clients: map[string]float64{"connected": 3}}
}

func newTestServer(b *fakeBroker) http.Handler {
	tokens := fakeIntrospector{
		"all": {Active: true, Subject: "usr_1", Audience: []string{aud}, Scopes: []string{
			ScopeClientsRead, ScopeClientsWrite, ScopeClientsDelete, ScopeCredentialsRotate, ScopeRolesRead, ScopeServerRead}},
		"readonly":  {Active: true, Subject: "usr_2", Audience: []string{aud}, Scopes: []string{ScopeClientsRead}},
		"otheraud":  {Active: true, Subject: "usr_3", Audience: []string{"mw-oauth"}, Scopes: []string{ScopeClientsRead, ScopeClientsWrite}},
		"inactive":  {Active: false},
		"nosubject": {Active: true, Audience: []string{aud}, Scopes: []string{ScopeClientsRead}},
	}
	return New(Options{
		Broker:         b,
		Stats:          fakeStats{},
		Auth:           identity.NewAuthenticator(aud, tokens),
		AllowedRoles:   []string{"nmnw"},
		ProtectedUsers: []string{"mqtt-admin", "mqtt-admin-api"},
	})
}

func do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEveryAdminRouteRequiresAValidToken(t *testing.T) {
	h := newTestServer(&fakeBroker{})
	routes := []struct{ method, path string }{
		{"GET", "/admin/api/server"}, {"GET", "/admin/api/stats"}, {"GET", "/admin/api/docs"}, {"GET", "/admin/api/docs/v1"}, {"GET", "/admin/api/roles"}, {"GET", "/admin/api/clients"},
		{"GET", "/admin/api/clients/gw1"}, {"POST", "/admin/api/clients"},
		{"POST", "/admin/api/clients/gw1/disable"}, {"POST", "/admin/api/clients/gw1/enable"},
		{"POST", "/admin/api/clients/gw1/password"}, {"DELETE", "/admin/api/clients/gw1"},
	}
	for _, r := range routes {
		for token, want := range map[string]int{"": 401, "garbage": 401, "inactive": 401, "nosubject": 401, "otheraud": 403, "readonly": 403} {
			if r.method == "GET" && r.path != "/admin/api/server" && r.path != "/admin/api/stats" && r.path != "/admin/api/docs" && r.path != "/admin/api/docs/v1" && r.path != "/admin/api/roles" && token == "readonly" {
				continue // readonly legitimately reads clients
			}
			if got := do(h, r.method, r.path, token, "").Code; got != want {
				t.Errorf("%s %s with %q: got %d, want %d", r.method, r.path, token, got, want)
			}
		}
	}
}

func TestUnmappedRoutesAreNotForwarded(t *testing.T) {
	b := &fakeBroker{}
	h := newTestServer(b)
	for _, p := range []string{"/admin/api/commands", "/admin/api/clients/gw1/roles", "/admin/api/dynsec", "/"} {
		if got := do(h, "POST", p, "all", `{}`).Code; got != 404 && got != 405 {
			t.Errorf("%s: got %d, want 404/405", p, got)
		}
	}
	if len(b.commands) != 0 {
		t.Fatalf("unmapped routes reached the broker: %v", b.commands)
	}
}

func TestCreateClientGeneratesPasswordOnceAndUsesAllowedRole(t *testing.T) {
	b := &fakeBroker{}
	h := newTestServer(b)
	rec := do(h, "POST", "/admin/api/clients", "all", `{"username":"nmnw-gateway-aabbccddeeff"}`)
	if rec.Code != 201 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp["password"]) < minPassword {
		t.Fatalf("generated password too short: %q", resp["password"])
	}
	if resp["role"] != "nmnw" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response %v / headers %v", resp, rec.Header())
	}
	if len(b.commands) != 2 {
		t.Fatalf("expected createClient then addClientRole, got %v", b.commands)
	}
	create, attach := b.commands[0], b.commands[1]
	if create["command"] != "createClient" || create["password"] != resp["password"] {
		t.Fatalf("createClient mismatch: %v", create)
	}
	if attach["command"] != "addClientRole" || attach["username"] != "nmnw-gateway-aabbccddeeff" || attach["rolename"] != "nmnw" {
		t.Fatalf("addClientRole mismatch: %v", attach)
	}
}

func TestCreateClientValidation(t *testing.T) {
	h := newTestServer(&fakeBroker{})
	cases := []struct {
		name, body string
		want       int
	}{
		{"bad username", `{"username":"../etc"}`, 400},
		{"role not allowed", `{"username":"gw1","role":"admin"}`, 400},
		{"protected user", `{"username":"mqtt-admin"}`, 403},
		{"own api user", `{"username":"mqtt-admin-api"}`, 403},
		{"short password", `{"username":"gw1","password":"short"}`, 400},
		{"control char password", "{\"username\":\"gw1\",\"password\":\"aaaaaaaaaaaaaaaaaaaaaaaa\\u0000b\"}", 400},
		{"unknown field", `{"username":"gw1","superuser":true}`, 400},
		{"not json", `nope`, 400},
	}
	for _, c := range cases {
		if got := do(h, "POST", "/admin/api/clients", "all", c.body).Code; got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestSuppliedPasswordIsNeverEchoed(t *testing.T) {
	h := newTestServer(&fakeBroker{})
	pw := strings.Repeat("x", 30)
	rec := do(h, "POST", "/admin/api/clients", "all", `{"username":"gw1","password":"`+pw+`"}`)
	if rec.Code != 201 || strings.Contains(rec.Body.String(), pw) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestProtectedUsersCannotBeChanged(t *testing.T) {
	b := &fakeBroker{}
	h := newTestServer(b)
	for _, r := range []struct{ method, path string }{
		{"DELETE", "/admin/api/clients/mqtt-admin"}, {"POST", "/admin/api/clients/mqtt-admin/disable"},
		{"POST", "/admin/api/clients/mqtt-admin-api/password"}, {"POST", "/admin/api/clients/mqtt-admin/enable"},
	} {
		if got := do(h, r.method, r.path, "all", "").Code; got != 403 {
			t.Errorf("%s %s: got %d, want 403", r.method, r.path, got)
		}
	}
	if len(b.commands) != 0 {
		t.Fatalf("protected operations reached the broker: %v", b.commands)
	}
}

func TestBrokerErrorsMapToStatuses(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{&dynsec.Error{Message: "Client not found"}, 404},
		{&dynsec.Error{Message: "Client already exists"}, 409},
		{&dynsec.Error{Message: "Invalid input"}, 400},
		{dynsec.ErrUnavailable, 503},
	}
	for _, c := range cases {
		h := newTestServer(&fakeBroker{err: c.err})
		if got := do(h, "DELETE", "/admin/api/clients/gw1", "all", "").Code; got != c.want {
			t.Errorf("%v: got %d, want %d", c.err, got, c.want)
		}
	}
}

func TestListClientsNormalisesBrokerReply(t *testing.T) {
	b := &fakeBroker{reply: json.RawMessage(`{"totalCount":1,"clients":[{"username":"gw1","disabled":true,"roles":[{"rolename":"nmnw","priority":-1}],"groups":[]}]}`)}
	rec := do(newTestServer(b), "GET", "/admin/api/clients", "readonly", "")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	want := `{"clients":[{"username":"gw1","disabled":true,"roles":["nmnw"]}]}`
	if strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("got %s, want %s", rec.Body, want)
	}
}

func TestRotateWithoutBodyGeneratesPassword(t *testing.T) {
	b := &fakeBroker{}
	rec := do(newTestServer(b), "POST", "/admin/api/clients/gw1/password", "all", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"password"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if b.last()["command"] != "setClientPassword" {
		t.Fatalf("wrong command %v", b.last())
	}
}

func TestHealthIsPublicAndTracksBrokerConnection(t *testing.T) {
	up := do(newTestServer(&fakeBroker{}), "GET", "/health", "", "")
	if up.Code != 200 || !strings.Contains(up.Body.String(), `"ok"`) {
		t.Fatalf("connected: %d %s", up.Code, up.Body)
	}
	for _, path := range []string{"/health", "/ready"} {
		down := do(newTestServer(&fakeBroker{down: true}), "GET", path, "", "")
		if down.Code != 503 || !strings.Contains(down.Body.String(), `"degraded"`) {
			t.Fatalf("%s with broker down: %d %s", path, down.Code, down.Body)
		}
		if strings.Contains(down.Body.String(), "broker") {
			t.Fatalf("public health must not describe internals: %s", down.Body)
		}
	}
}

func TestStatsRequiresServerReadAndReturnsSnapshot(t *testing.T) {
	h := newTestServer(&fakeBroker{})
	if got := do(h, "GET", "/admin/api/stats", "readonly", "").Code; got != 403 {
		t.Fatalf("readonly token: got %d, want 403", got)
	}
	rec := do(h, "GET", "/admin/api/stats", "all", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"version":"2.1.2"`) || !strings.Contains(rec.Body.String(), `"connected":3`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestDocsListAndLanguageSelection(t *testing.T) {
	h := newTestServer(&fakeBroker{})

	list := do(h, "GET", "/admin/api/docs", "all", "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"version":"v1"`) ||
		!strings.Contains(list.Body.String(), `"content_type":"text/markdown"`) {
		t.Fatalf("list: %d %s", list.Code, list.Body)
	}

	for lang, want := range map[string]string{
		"":      "Connecting a client",
		"en":    "Connecting a client",
		"pt":    "Conectando um cliente",
		"pt-BR": "Conectando um cliente",
		"fr":    "Connecting a client", // unsupported: English
	} {
		rec := do(h, "GET", "/admin/api/docs/v1?lang="+lang, "all", "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("lang %q: %d, missing %q", lang, rec.Code, want)
		}
	}

	var doc map[string]string
	_ = json.Unmarshal(do(h, "GET", "/admin/api/docs/v1", "all", "").Body.Bytes(), &doc)
	if doc["version"] != "v1" || doc["status"] != "stable" || doc["documentation"] == "" {
		t.Fatalf("unexpected document shape: %v", doc)
	}
}

func TestDocsUnknownOrMalformedVersionsAreNotFound(t *testing.T) {
	h := newTestServer(&fakeBroker{})
	for _, v := range []string{"v2", "v0", "latest", "..", "v1.en", "V1", "v1%2F..", "v9999"} {
		got := do(h, "GET", "/admin/api/docs/"+v, "all", "").Code
		// The router cleans "/docs/.." into a redirect to the parent before any handler
		// runs, so that request never reaches the docs code. Everything else is a 404.
		if got != 404 && !(v == ".." && got == 307) {
			t.Errorf("version %q: got %d, want 404", v, got)
		}
	}
}

// Keeps the published documentation honest: every scope, error code and route the API
// defines must be described, in both languages.
func TestDocsDescribeEveryScopeRouteAndErrorCode(t *testing.T) {
	h := newTestServer(&fakeBroker{})
	scopes := []string{ScopeClientsRead, ScopeClientsWrite, ScopeClientsDelete,
		ScopeCredentialsRotate, ScopeRolesRead, ScopeServerRead}
	routes := []string{
		"GET /server", "GET /stats", "GET /roles", "GET /clients", "GET /clients/{username}",
		"POST /clients", "POST /clients/{username}/disable", "POST /clients/{username}/enable",
		"POST /clients/{username}/password", "DELETE /clients/{username}",
		"GET /docs", "GET /docs/{version}",
		"GET /roles/{name}", "POST /roles", "DELETE /roles/{name}", "POST /roles/{name}/acls",
		"POST /roles/{name}/acls/remove", "PUT /clients/{username}/roles/{role}",
		"DELETE /clients/{username}/roles/{role}",
	}
	codes := []string{"unauthorized", "forbidden", "protected_user", "invalid_username",
		"role_not_allowed", "already_exists", "not_found", "broker_unavailable", "too_many_failures",
		"role_required", "invalid_role", "reserved_role", "role_in_use", "invalid_acl",
		"forbidden_topic", "invalid_description", "$CONTROL", "dynsec-admin", "mqtt.roles.write", "mqtt.roles.delete"}

	for _, lang := range []string{"en", "pt"} {
		body := do(h, "GET", "/admin/api/docs/v1?lang="+lang, "all", "").Body.String()
		var doc map[string]string
		_ = json.Unmarshal([]byte(body), &doc)
		text := doc["documentation"]
		auth := []string{"ADMIN_AUTH_MODE", "MQTT_ADMIN_TOKENS", "mqtt-admin token new", "Authorization: Bearer",
			"`read`", "`write`", "`admin`", "federated"}
		for _, item := range append(append(append(scopes, routes...), codes...), auth...) {
			if !strings.Contains(text, item) {
				t.Errorf("%s docs do not mention %q", lang, item)
			}
		}
	}
}
