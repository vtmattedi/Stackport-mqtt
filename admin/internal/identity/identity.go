// Package identity validates MW Identity delegated tokens by authenticated
// introspection. The contract mirrors the other MW resource servers: the token must be
// active, carry a subject, name this service in its audience, and include the scope the
// route requires. Any failure to introspect denies the request.
package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vtmattedi/stackport-mqtt/admin/internal/auth"
)

const maxIntrospectionBody = 64 << 10

type Token struct {
	Active   bool
	Subject  string
	Audience []string
	Scopes   []string
}

type Introspector interface {
	Introspect(ctx context.Context, rawToken string) (Token, error)
}

type Client struct {
	endpoint     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

func NewClient(baseURL, clientID, clientSecret string, timeout time.Duration) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil {
		return nil, fmt.Errorf("invalid Identity base URL")
	}
	if strings.TrimSpace(clientID) == "" || clientSecret == "" {
		return nil, fmt.Errorf("Identity introspection credentials are required")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/oauth/introspect"
	base.RawQuery, base.Fragment = "", ""
	return &Client{
		endpoint:     base.String(),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: clientSecret,
		httpClient: &http.Client{
			Timeout: timeout,
			// A redirect would carry the client credentials somewhere unreviewed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) Introspect(ctx context.Context, rawToken string) (Token, error) {
	form := url.Values{"token": []string{rawToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("introspection: create request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("introspection: transport")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxIntrospectionBody))
		return Token{}, fmt.Errorf("introspection: status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxIntrospectionBody+1))
	if err != nil || len(body) > maxIntrospectionBody {
		return Token{}, fmt.Errorf("introspection: invalid response body")
	}
	var payload struct {
		Active   bool            `json:"active"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Scope    string          `json:"scope"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return Token{}, fmt.Errorf("introspection: invalid response JSON")
	}
	return Token{
		Active:   payload.Active,
		Subject:  strings.TrimSpace(payload.Subject),
		Audience: audiences(payload.Audience),
		Scopes:   strings.Fields(payload.Scope),
	}, nil
}

// audiences accepts both a single string and an array, as the other services do.
func audiences(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return nonEmpty([]string{one})
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return nonEmpty(many)
	}
	return nil
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

type Authenticator struct {
	audience string
	client   Introspector
}

func NewAuthenticator(audience string, client Introspector) *Authenticator {
	return &Authenticator{audience: strings.TrimSpace(audience), client: client}
}

// Require wraps next so it only runs for a valid delegated token holding requiredScope.
func (a *Authenticator) Require(requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			a.reject(w, r, http.StatusUnauthorized, "token_missing_or_malformed")
			return
		}
		parts := strings.Fields(values[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			a.reject(w, r, http.StatusUnauthorized, "token_malformed")
			return
		}
		token, err := a.client.Introspect(r.Context(), parts[1])
		switch {
		case err != nil:
			a.reject(w, r, http.StatusUnauthorized, "introspection_failed")
			return
		case !token.Active:
			a.reject(w, r, http.StatusUnauthorized, "token_inactive")
			return
		case token.Subject == "":
			a.reject(w, r, http.StatusUnauthorized, "subject_missing")
			return
		case !contains(token.Audience, a.audience):
			a.reject(w, r, http.StatusForbidden, "audience_mismatch")
			return
		case !contains(token.Scopes, requiredScope):
			a.reject(w, r, http.StatusForbidden, "scope_missing")
			return
		}
		// Subject is the immutable Identity `sub`.
		principal := auth.Principal{Subject: token.Subject, Scopes: append([]string(nil), token.Scopes...)}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

func (a *Authenticator) reject(w http.ResponseWriter, r *http.Request, status int, reason string) {
	slog.WarnContext(r.Context(), "authentication rejected", "reason", reason, "path", r.URL.Path)
	message := "unauthorized"
	if status == http.StatusForbidden {
		message = "forbidden"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, message)
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
