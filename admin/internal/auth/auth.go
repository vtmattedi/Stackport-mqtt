// Package auth is the contract between the HTTP API and an authentication mode. A mode
// turns a request into a Principal holding scopes; the API only asks whether the caller
// holds the scope a route needs.
package auth

import (
	"context"
	"net/http"
)

// Principal is the authenticated caller. Subject is stable and safe to log: the MW
// Identity `sub` in federated mode, or `token:<name>` in token mode.
type Principal struct {
	Subject string
	Scopes  []string
}

// Authorizer wraps a handler so it only runs for a caller holding requiredScope.
type Authorizer interface {
	Require(requiredScope string, next http.Handler) http.Handler
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
