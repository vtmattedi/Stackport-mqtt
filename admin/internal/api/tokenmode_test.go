package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/tokenauth"
)

// The whole API behind the standalone token authenticator, with no MW Identity involved.
func newTokenServer(t *testing.T, b *fakeBroker) (http.Handler, map[string]string) {
	return newTokenServerWith(t, b, nil)
}

// newTokenServerWith lets a test adjust the API options before the server is built.
func newTokenServerWith(t *testing.T, b *fakeBroker, mutate func(*Options)) (http.Handler, map[string]string) {
	t.Helper()
	if b.reply == nil {
		// One reply shape that satisfies the list, get and roles handlers.
		b.reply = json.RawMessage(`{"clients":[],"client":{"username":"gw1"},"roles":[]}`)
	}
	tokens := map[string]string{
		"reader": "mqa_reader-token-aaaaaaaaaaaaaaaaaaaa",
		"writer": "mqa_writer-token-bbbbbbbbbbbbbbbbbbbb",
		"admin":  "mqa_admin-token-cccccccccccccccccccc",
	}
	specs := map[string]string{"reader": "read", "writer": "write", "admin": "admin"}
	var entries []string
	for name, token := range tokens {
		entries = append(entries, tokenauth.FormatEntry(name, tokenauth.Hash(token), specs[name], ""))
	}
	parsed, err := tokenauth.ParseEntries(strings.Join(entries, ";"))
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		Broker:         b,
		Stats:          fakeStats{},
		Auth:           tokenauth.New(parsed),
		AllowedRoles:   []string{"nmnw"},
		ProtectedUsers: []string{"mqtt-admin"},
	}
	if mutate != nil {
		mutate(&opts)
	}
	return New(opts), tokens
}

func TestTokenModeEnforcesScopesOnEveryRoute(t *testing.T) {
	h, tokens := newTokenServer(t, &fakeBroker{})

	type route struct{ method, path, body string }
	reads := []route{
		{"GET", "/admin/api/server", ""}, {"GET", "/admin/api/stats", ""},
		{"GET", "/admin/api/roles", ""}, {"GET", "/admin/api/clients", ""},
		{"GET", "/admin/api/clients/gw1", ""}, {"GET", "/admin/api/docs", ""},
		{"GET", "/admin/api/docs/v1", ""},
	}
	writes := []route{
		{"POST", "/admin/api/clients", `{"username":"gw1"}`},
		{"POST", "/admin/api/clients/gw1/disable", ""},
		{"POST", "/admin/api/clients/gw1/enable", ""},
		{"POST", "/admin/api/clients/gw1/password", ""},
	}
	deletes := []route{{"DELETE", "/admin/api/clients/gw1", ""}}

	check := func(label string, who string, rs []route, want func(code int) bool) {
		for _, r := range rs {
			if code := do(h, r.method, r.path, tokens[who], r.body).Code; !want(code) {
				t.Errorf("%s %s %s: got %d", label, r.method, r.path, code)
			}
		}
	}
	ok := func(code int) bool { return code >= 200 && code < 300 }
	forbidden := func(code int) bool { return code == 403 }

	check("reader reads", "reader", reads, ok)
	check("reader cannot write", "reader", writes, forbidden)
	check("reader cannot delete", "reader", deletes, forbidden)
	check("writer reads", "writer", reads, ok)
	check("writer writes", "writer", writes, ok)
	check("writer cannot delete", "writer", deletes, forbidden)
	check("admin deletes", "admin", deletes, ok)
}

func TestTokenModeRejectsMissingAndWrongTokens(t *testing.T) {
	h, tokens := newTokenServer(t, &fakeBroker{})
	for name, token := range map[string]string{
		"none":      "",
		"unknown":   "mqa_not-a-configured-token-0000000000",
		"truncated": tokens["admin"][:20],
		"hash":      tokenauth.Hash(tokens["admin"]),
	} {
		if got := do(h, "GET", "/admin/api/clients", token, "").Code; got != 401 {
			t.Errorf("%s: got %d, want 401", name, got)
		}
	}
	// Health stays public in every mode.
	if got := do(h, "GET", "/health", "", "").Code; got != 200 {
		t.Errorf("health: %d", got)
	}
}

func TestTokenModeKeepsAllTheAdminGuardrails(t *testing.T) {
	b := &fakeBroker{}
	h, tokens := newTokenServer(t, b)

	// A token with every scope still cannot touch protected users or unassignable roles.
	if got := do(h, "DELETE", "/admin/api/clients/mqtt-admin", tokens["admin"], "").Code; got != 403 {
		t.Errorf("deleting a protected client: %d", got)
	}
	if got := do(h, "POST", "/admin/api/clients", tokens["admin"], `{"username":"x1","role":"admin"}`).Code; got != 400 {
		t.Errorf("assigning a reserved role: %d", got)
	}
	if len(b.commands) != 0 {
		t.Fatalf("guardrails must stop the request before the broker: %v", b.commands)
	}

	// A normal create works and returns the generated password exactly once.
	rec := do(h, "POST", "/admin/api/clients", tokens["writer"], `{"username":"gw2"}`)
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 201 || len(out["password"]) < minPassword {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
}

func TestTokenModeFailedAuthIsRateLimited(t *testing.T) {
	good := "mqa_good-0123456789012345678901234567"
	parsed, err := tokenauth.ParseEntries("ci:" + tokenauth.Hash(good) + ":read")
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{
		Broker: &fakeBroker{}, Stats: fakeStats{}, Auth: tokenauth.New(parsed),
		AllowedRoles: []string{"nmnw"}, AuthFailureLimit: 3,
	})

	var last int
	for i := 0; i < 6; i++ {
		last = do(h, "GET", "/admin/api/clients", "mqa_bad-0123456789012345678901234567", "").Code
	}
	if last != 429 {
		t.Fatalf("expected 429 after repeated failures, got %d", last)
	}
	if got := do(h, "GET", "/admin/api/clients", good, "").Code; got != 429 {
		t.Fatalf("a blocked address stays blocked for the window, even with a good token: %d", got)
	}
}
