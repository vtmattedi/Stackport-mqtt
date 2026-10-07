// Package tokenauth implements the standalone authentication mode: static bearer tokens
// configured in the environment. Only a SHA-256 hash of each token is ever configured, so
// the environment cannot be used to authenticate; the token itself is shown once, when it
// is generated.
//
// Entry syntax, entries separated by ';' or newlines:
//
//	name:sha256hex:scopes[:expires]
//
// scopes are scope names or the presets read, write, admin, joined with '+'. expires is a
// date (valid through the end of that day, UTC) or an RFC 3339 time; omit it for no expiry.
package tokenauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/auth"
	"github.com/vtmattedi/stackport-mqtt/admin/internal/scopes"
)

const (
	// Prefix marks tokens this service generates, which makes them recognisable in
	// secret scanners and password managers.
	Prefix = "mqa_"

	// MinTokenLength is the shortest token the helper accepts for a token you bring
	// yourself. Generated tokens are 47 characters.
	MinTokenLength = 32

	maxEntries     = 100
	maxHeaderToken = 256
)

var (
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Entry is one configured token.
type Entry struct {
	Name      string
	Hash      [sha256.Size]byte
	Scopes    []string
	ExpiresAt time.Time // zero means no expiry
}

// ParseEntries parses the MQTT_ADMIN_TOKENS value. Any problem is reported with the
// entry's name or position, never with a hash or token.
func ParseEntries(raw string) ([]Entry, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' })
	var entries []Entry
	names := map[string]bool{}
	hashes := map[[sha256.Size]byte]string{}

	for i, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		where := fmt.Sprintf("token entry %d", i+1)
		// At most four parts: an RFC 3339 expiry contains colons of its own, and the
		// first three fields can never contain one.
		parts := strings.SplitN(field, ":", 4)
		if len(parts) < 3 {
			return nil, fmt.Errorf("%s: expected name:sha256:scopes[:expires]", where)
		}
		name := strings.TrimSpace(parts[0])
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("%s: name must be 1-64 characters of a-z, 0-9, '.', '_' or '-'", where)
		}
		where = fmt.Sprintf("token %q", name)
		if names[name] {
			return nil, fmt.Errorf("%s: duplicate name", where)
		}
		hash := strings.ToLower(strings.TrimSpace(parts[1]))
		if !hashPattern.MatchString(hash) {
			return nil, fmt.Errorf("%s: the second field must be a 64-character SHA-256 hex digest of the token, not the token itself", where)
		}
		var digest [sha256.Size]byte
		decoded, _ := hex.DecodeString(hash)
		copy(digest[:], decoded)
		if other, dup := hashes[digest]; dup {
			return nil, fmt.Errorf("%s: same token as %q", where, other)
		}

		granted, err := expandScopes(parts[2])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}

		var expires time.Time
		if len(parts) == 4 {
			expires, err = parseExpiry(strings.TrimSpace(parts[3]))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
		}

		names[name] = true
		hashes[digest] = name
		entries = append(entries, Entry{Name: name, Hash: digest, Scopes: granted, ExpiresAt: expires})
		if len(entries) > maxEntries {
			return nil, fmt.Errorf("at most %d tokens are supported", maxEntries)
		}
	}
	return entries, nil
}

func expandScopes(spec string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, word := range strings.Split(spec, "+") {
		word = strings.TrimSpace(word)
		if word == "" {
			return nil, fmt.Errorf("empty scope in %q", spec)
		}
		expanded, ok := scopes.Expand(word)
		if !ok {
			return nil, fmt.Errorf("unknown scope %q (presets: %s; scopes: %s)",
				word, strings.Join(scopes.Presets(), ", "), strings.Join(scopes.All(), ", "))
		}
		for _, scope := range expanded {
			if !seen[scope] {
				seen[scope] = true
				out = append(out, scope)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func parseExpiry(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty expiry (omit the field for no expiry)")
	}
	if day, err := time.Parse("2006-01-02", value); err == nil {
		return day.Add(24*time.Hour - time.Second), nil // valid through the end of that day
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expiry %q must be YYYY-MM-DD or an RFC 3339 time", value)
}

// Generate returns a new random token: 32 bytes of entropy, URL-safe.
func Generate() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Hash returns the hex SHA-256 of a token, which is what goes into the configuration.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Authenticator checks bearer tokens against the configured entries.
type Authenticator struct {
	entries []Entry
	now     func() time.Time
}

func New(entries []Entry) *Authenticator {
	return &Authenticator{entries: entries, now: time.Now}
}

// Require implements auth.Authorizer.
func (a *Authenticator) Require(requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			a.reject(w, r, http.StatusUnauthorized, "token_missing_or_malformed", "")
			return
		}
		parts := strings.Fields(values[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > maxHeaderToken {
			a.reject(w, r, http.StatusUnauthorized, "token_malformed", "")
			return
		}

		entry, ok := a.match(parts[1])
		switch {
		case !ok:
			a.reject(w, r, http.StatusUnauthorized, "token_unknown", "")
			return
		case !entry.ExpiresAt.IsZero() && a.now().After(entry.ExpiresAt):
			a.reject(w, r, http.StatusUnauthorized, "token_expired", entry.Name)
			return
		case !has(entry.Scopes, requiredScope):
			a.reject(w, r, http.StatusForbidden, "scope_missing", entry.Name)
			return
		}
		principal := auth.Principal{Subject: "token:" + entry.Name, Scopes: append([]string(nil), entry.Scopes...)}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

// match compares the presented token's hash with every configured hash, without stopping
// at the first hit, so timing does not reveal how many tokens exist or which one matched.
func (a *Authenticator) match(token string) (Entry, bool) {
	sum := sha256.Sum256([]byte(token))
	var found Entry
	matched := 0
	for _, e := range a.entries {
		if subtle.ConstantTimeCompare(sum[:], e.Hash[:]) == 1 {
			found = e
			matched = 1
		}
	}
	return found, matched == 1
}

func (a *Authenticator) reject(w http.ResponseWriter, r *http.Request, status int, reason, name string) {
	attrs := []any{"reason", reason, "path", r.URL.Path}
	if name != "" {
		attrs = append(attrs, "token", name) // the name, never the token or its hash
	}
	slog.WarnContext(r.Context(), "authentication rejected", attrs...)
	message := "unauthorized"
	if status == http.StatusForbidden {
		message = "forbidden"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, message)
}

func has(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
