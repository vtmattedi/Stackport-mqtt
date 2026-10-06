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
}

func (f *fakeBroker) Do(_ context.Context, c map[string]any) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, c)
	return f.reply, f.err
}
func (f *fakeBroker) Connected() bool { return true }
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
		{"GET", "/admin/api/server"}, {"GET", "/admin/api/stats"}, {"GET", "/admin/api/roles"}, {"GET", "/admin/api/clients"},
		{"GET", "/admin/api/clients/gw1"}, {"POST", "/admin/api/clients"},
		{"POST", "/admin/api/clients/gw1/disable"}, {"POST", "/admin/api/clients/gw1/enable"},
		{"POST", "/admin/api/clients/gw1/password"}, {"DELETE", "/admin/api/clients/gw1"},
	}
	for _, r := range routes {
		for token, want := range map[string]int{"": 401, "garbage": 401, "inactive": 401, "nosubject": 401, "otheraud": 403, "readonly": 403} {
			if r.method == "GET" && r.path != "/admin/api/server" && r.path != "/admin/api/stats" && r.path != "/admin/api/roles" && token == "readonly" {
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
	cmd := b.last()
	if cmd["command"] != "createClient" || cmd["password"] != resp["password"] {
		t.Fatalf("broker command mismatch: %v", cmd)
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

func TestHealthIsPublic(t *testing.T) {
	if got := do(newTestServer(&fakeBroker{}), "GET", "/health", "", "").Code; got != 200 {
		t.Fatalf("health: %d", got)
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
