// Package middleware provides the Sovereign REST API middleware chain.
//
// The chain is composed in a fixed order by Chain/NewHandler: request-id,
// panic-recover, body-limit, per-route timeout, CORS, rate-limit, authn,
// CSRF, scope authz, conditional-request, idempotency, handler, problem+json
// mapper, access log. This file defines the request-scoped values (request ID,
// principal) that the chain reads and writes via context.
package middleware

import (
	"context"
)

// requestIDKey is the context key for the request ID.
type requestIDKey struct{}

// ctxRequestID returns the request ID set by RequestID, or "".
func ctxRequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// principalKey is the context key for the authenticated Principal.
type principalKey struct{}

// Principal is the authenticated identity for a request, set by AuthN into
// the request context. IsCookie distinguishes browser (cookie) principals from
// bearer (programmatic) principals so later middleware (CSRF, access log) can
// branch on the credential type.
type Principal struct {
	UserID   string
	TenantID string
	Scopes   []string
	IsAdmin  bool
	IsCookie bool
}

// WithPrincipal returns a copy of ctx carrying the authenticated principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext returns the authenticated principal, or nil.
func PrincipalFromContext(ctx context.Context) *Principal {
	if v, ok := ctx.Value(principalKey{}).(*Principal); ok {
		return v
	}
	return nil
}

// RequestIDFromContext returns the request ID, or "".
func RequestIDFromContext(ctx context.Context) string { return ctxRequestID(ctx) }
