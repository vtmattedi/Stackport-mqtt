package tokenauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/auth"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/scopes"
)

func entryFor(t *testing.T, name, token, scopeSpec, expires string) string {
	t.Helper()
	return FormatEntry(name, Hash(token), scopeSpec, expires)
}

func TestParseEntriesExpandsPresetsAndScopes(t *testing.T) {
	raw := strings.Join([]string{
		"ci:" + Hash("a") + ":read",
		"ops:" + Hash("b") + ":write+mqtt.clients.delete:2030-01-31",
		"all:" + Hash("c") + ":admin:2030-01-31T10:00:00Z",
	}, ";\n")
	entries, err := ParseEntries(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries", len(entries))
	}

	if got := strings.Join(entries[0].Scopes, ","); got != "mqtt.clients.read,mqtt.roles.read,mqtt.server.read" {
		t.Errorf("read preset = %s", got)
	}
	if !entries[0].ExpiresAt.IsZero() {
		t.Error("no expiry was given")
	}
	ops := strings.Join(entries[1].Scopes, ",")
	for _, want := range []string{scopes.ClientsWrite, scopes.CredentialsRotate, scopes.ClientsDelete, scopes.ClientsRead} {
		if !strings.Contains(ops, want) {
			t.Errorf("ops is missing %s: %s", want, ops)
		}
	}
	if want := time.Date(2030, 1, 31, 23, 59, 59, 0, time.UTC); !entries[1].ExpiresAt.Equal(want) {
		t.Errorf("a date expires at the end of that day UTC: got %s", entries[1].ExpiresAt)
	}
	if len(entries[2].Scopes) != len(scopes.All()) {
		t.Errorf("admin preset has %d scopes, want %d", len(entries[2].Scopes), len(scopes.All()))
	}
	if want := time.Date(2030, 1, 31, 10, 0, 0, 0, time.UTC); !entries[2].ExpiresAt.Equal(want) {
		t.Errorf("RFC 3339 expiry: got %s", entries[2].ExpiresAt)
	}
}

func TestParseEntriesRejectsBadConfiguration(t *testing.T) {
	good := Hash("token")
	cases := map[string]string{
		"missing fields":     "ci:" + good,
		"too many fields":    "ci:" + good + ":read:2030-01-01:extra",
		"bad name":           "CI Bot:" + good + ":read",
		"empty name":         ":" + good + ":read",
		"token not hash":     "ci:mqa_thisIsTheTokenItselfNotAHash:read",
		"short hash":         "ci:abcd:read",
		"uppercase fine but": "ci:" + strings.Repeat("z", 64) + ":read",
		"unknown scope":      "ci:" + good + ":superuser",
		"empty scope":        "ci:" + good + ":read+",
		"empty scopes":       "ci:" + good + ":",
		"bad expiry":         "ci:" + good + ":read:next-tuesday",
		"empty expiry":       "ci:" + good + ":read:",
		"duplicate name":     "ci:" + good + ":read;ci:" + Hash("other") + ":read",
		"duplicate token":    "a:" + good + ":read;b:" + good + ":write",
	}
	for name, raw := range cases {
		if _, err := ParseEntries(raw); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseEntriesNeverEchoesAHash(t *testing.T) {
	h := Hash("secret")
	_, err := ParseEntries("ci:" + h + ":bogus")
	if err == nil || strings.Contains(err.Error(), h) {
		t.Fatalf("error must not contain the hash: %v", err)
	}
}

func TestEmptyConfigurationParsesToNothing(t *testing.T) {
	entries, err := ParseEntries("  \n ; ;\n")
	if err != nil || len(entries) != 0 {
		t.Fatalf("got %v, %v", entries, err)
	}
}

func serve(a *Authenticator, scope, header string) (*httptest.ResponseRecorder, *auth.Principal) {
	var seen *auth.Principal
	h := a.Require(scope, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := auth.PrincipalFrom(r.Context()); ok {
			seen = &p
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, seen
}

func TestAuthenticatorChecksTokenExpiryAndScope(t *testing.T) {
	reader, writer, expired := "mqa_reader-token-0123456789", "mqa_writer-token-0123456789", "mqa_expired-token-0123456789"
	entries, err := ParseEntries(strings.Join([]string{
		entryFor(t, "reader", reader, "read", ""),
		entryFor(t, "writer", writer, "write", "2099-01-01"),
		entryFor(t, "old", expired, "admin", "2000-01-01"),
	}, ";"))
	if err != nil {
		t.Fatal(err)
	}
	a := New(entries)

	rec, p := serve(a, scopes.ClientsRead, "Bearer "+reader)
	if rec.Code != 200 || p == nil || p.Subject != "token:reader" {
		t.Fatalf("reader: %d %v", rec.Code, p)
	}
	if rec, _ := serve(a, scopes.ClientsWrite, "Bearer "+reader); rec.Code != 403 {
		t.Errorf("a read token must not write: %d", rec.Code)
	}
	if rec, _ := serve(a, scopes.ClientsDelete, "Bearer "+writer); rec.Code != 403 {
		t.Errorf("the write preset has no delete: %d", rec.Code)
	}
	if rec, _ := serve(a, scopes.CredentialsRotate, "Bearer "+writer); rec.Code != 200 {
		t.Errorf("write can rotate: %d", rec.Code)
	}
	if rec, _ := serve(a, scopes.ClientsRead, "Bearer "+expired); rec.Code != 401 {
		t.Errorf("an expired token must be refused even with every scope: %d", rec.Code)
	}
}

func TestAuthenticatorRefusesUnknownAndMalformedCredentials(t *testing.T) {
	entries, _ := ParseEntries(entryFor(t, "ci", "mqa_known-token-0123456789", "admin", ""))
	a := New(entries)

	for name, header := range map[string]string{
		"none":              "",
		"wrong token":       "Bearer mqa_other-token-0123456789",
		"the hash itself":   "Bearer " + Hash("mqa_known-token-0123456789"),
		"basic scheme":      "Basic bXFhX2tub3duLXRva2VuLTAxMjM0NTY3ODk=",
		"no scheme":         "mqa_known-token-0123456789",
		"empty bearer":      "Bearer ",
		"extra parts":       "Bearer mqa_known-token-0123456789 extra",
		"oversized":         "Bearer " + strings.Repeat("a", 1000),
		"token plus suffix": "Bearer mqa_known-token-0123456789x",
	} {
		if rec, p := serve(a, scopes.ServerRead, header); rec.Code != 401 || p != nil {
			t.Errorf("%s: got %d (principal %v), want 401", name, rec.Code, p)
		}
	}

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Add("Authorization", "Bearer mqa_known-token-0123456789")
	req.Header.Add("Authorization", "Bearer mqa_known-token-0123456789")
	rec := httptest.NewRecorder()
	a.Require(scopes.ServerRead, http.NotFoundHandler()).ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("two Authorization headers must be refused: %d", rec.Code)
	}
}

func TestNoTokensMeansNothingIsAccepted(t *testing.T) {
	a := New(nil)
	if rec, _ := serve(a, scopes.ServerRead, "Bearer mqa_anything-at-all-0123456789"); rec.Code != 401 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestGenerateAndHash(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Generate()
	if a == b || !strings.HasPrefix(a, Prefix) || len(a) < MinTokenLength {
		t.Fatalf("tokens must be unique, prefixed and long: %q %q", a, b)
	}
	if len(Hash(a)) != 64 || Hash(a) == Hash(b) {
		t.Fatal("hash must be 64 hex characters and differ per token")
	}
}

func TestCLINewProducesAWorkingTokenAndEntry(t *testing.T) {
	var out, errOut bytes.Buffer
	code := RunCLI([]string{"new", "--name", "ci", "--scopes", "read,mqtt.clients.write", "--expires", "2099-12-31"},
		strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	lines := strings.Split(out.String(), "\n")
	var token, entry string
	for i, line := range lines {
		if strings.HasPrefix(line, Prefix) {
			token = strings.TrimSpace(line)
		}
		if strings.HasPrefix(line, "Add this entry") && i+1 < len(lines) {
			entry = strings.TrimSpace(lines[i+1])
		}
	}
	if token == "" || entry == "" {
		t.Fatalf("output lacks the token or the entry:\n%s", out.String())
	}
	if strings.Contains(entry, token) {
		t.Fatal("the configuration entry must never contain the token")
	}

	entries, err := ParseEntries(entry)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the printed entry must parse: %v", err)
	}
	if rec, _ := serve(New(entries), scopes.ClientsWrite, "Bearer "+token); rec.Code != 200 {
		t.Fatalf("the printed token must authenticate against the printed entry: %d", rec.Code)
	}
	if rec, _ := serve(New(entries), scopes.ClientsDelete, "Bearer "+token); rec.Code != 403 {
		t.Fatalf("and only for the scopes asked: %d", rec.Code)
	}
}

func TestCLIRejectsBadInput(t *testing.T) {
	cases := [][]string{
		{},
		{"bogus"},
		{"new"},
		{"new", "--name", "ci"},
		{"new", "--scopes", "read"},
		{"new", "--name", "Bad Name", "--scopes", "read"},
		{"new", "--name", "ci", "--scopes", "nope"},
		{"new", "--name", "ci", "--scopes", "read", "--expires", "soon"},
	}
	for _, args := range cases {
		var out, errOut bytes.Buffer
		if code := RunCLI(args, strings.NewReader(""), &out, &errOut); code == 0 {
			t.Errorf("%v: expected a non-zero exit", args)
		}
		if strings.Contains(out.String(), Prefix) {
			t.Errorf("%v: a token must not be printed on failure", args)
		}
	}
}

func TestCLIHash(t *testing.T) {
	token := "mqa_bring-your-own-token-0123456789"
	var out, errOut bytes.Buffer
	if code := RunCLI([]string{"hash"}, strings.NewReader(token+"\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != Hash(token) {
		t.Fatalf("got %q", out.String())
	}
	out.Reset()
	if code := RunCLI([]string{"hash"}, strings.NewReader("short\n"), &out, &errOut); code == 0 || out.Len() != 0 {
		t.Fatal("a weak token must be refused")
	}
	if code := RunCLI([]string{"hash"}, strings.NewReader(""), &out, &errOut); code == 0 {
		t.Fatal("no input must fail")
	}
}
