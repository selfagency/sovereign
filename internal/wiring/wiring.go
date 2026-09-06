// Package wiring implements the concrete TokenValidator and ACLChecker
// interfaces that the protocol handlers depend on, bridging them to the
// auth and tenant stores. This is the integration glue that makes
// remoteStorage and Solid enforce authorization.
package wiring

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/protocols/remotestorage"
	"github.com/selfagency/sovereign/internal/protocols/solid"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// TokenValidator validates bearer access tokens against the OIDC signing key.
// It implements remotestorage.TokenValidator. Only short-lived signed access
// tokens are accepted — refresh tokens are rejected (token-type separation).
type TokenValidator struct {
	Key      *rsa.PrivateKey
	Issuer   string
	Audience string
}

// ValidateToken returns the scopes for a bearer access token, or an error if
// the token is invalid.
func (v *TokenValidator) ValidateToken(ctx context.Context, token string) ([]string, error) {
	if token == "" {
		return nil, errors.New("wiring: empty token")
	}
	claims, err := auth.ValidateAccessToken(v.Key, token, v.Issuer, v.Audience)
	if err != nil {
		return nil, errors.New("wiring: invalid token")
	}
	return claims.Scopes, nil
}

// Ensure TokenValidator satisfies the interface.
var _ remotestorage.TokenValidator = (*TokenValidator)(nil)

// SubjectValidator validates a bearer access token and returns the
// authenticated subject. It implements solid.TokenValidator, deriving the
// agent's WebID from the token's subject.
type SubjectValidator struct {
	Key      *rsa.PrivateKey
	Issuer   string
	Audience string
}

// ValidateToken returns the subject for a bearer access token, or an error if
// the token is invalid. For Solid-OIDC, the webid claim (the agent's WebID)
// takes precedence over sub; a token without a webid claim falls back to sub.
func (v *SubjectValidator) ValidateToken(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", errors.New("wiring: empty token")
	}
	claims, err := auth.ValidateAccessToken(v.Key, token, v.Issuer, v.Audience)
	if err != nil {
		return "", errors.New("wiring: invalid token")
	}
	if claims.WebID != "" {
		return claims.WebID, nil
	}
	return claims.Subject, nil
}

// Ensure SubjectValidator satisfies the interface.
var _ solid.TokenValidator = (*SubjectValidator)(nil)

// ACLChecker authorizes Solid LDP access based on tenant ownership.
// It implements solid.ACLChecker.
type ACLChecker struct {
	Store *store.Store
}

// CanRead reports whether agent may read resource. Public reads are allowed
// (the LDP subset serves published content); authenticated agents may read
// their own tenant's resources.
func (a *ACLChecker) CanRead(ctx context.Context, resource string, agent solid.Agent) bool {
	if agent.WebID == "" {
		// Public read is allowed for published content.
		return true
	}
	return a.ownsTenant(ctx, agent.WebID)
}

// CanWrite reports whether agent may write resource. Only an account whose
// WebID resolves to the request's tenant may write.
func (a *ACLChecker) CanWrite(ctx context.Context, resource string, agent solid.Agent) bool {
	if agent.WebID == "" {
		return false
	}
	return a.ownsTenant(ctx, agent.WebID)
}

// ownsTenant reports whether the WebID resolves to an account in the tenant
// carried by the request context.
func (a *ACLChecker) ownsTenant(ctx context.Context, webID string) bool {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return false
	}
	acct, err := a.Store.AccountByWebID(ctx, webID)
	if err != nil {
		return false
	}
	return acct.TenantID == t.ID
}

// Ensure ACLChecker satisfies solid.ACLChecker.
var _ solid.ACLChecker = (*ACLChecker)(nil)

// scopeImplies maps a granted scope to the set of scopes it satisfies.
// Exact matching only - the implication table is the sole source of
// hierarchical relationships. No prefix logic.
var scopeImplies = map[string][]string{
	// Add implications only when the API taxonomy needs them, e.g.
	// "profile:write": {"profile:read"}.
}

// ScopesContains reports whether scopes contains want, either by exact match
// or via an explicit implication in scopeImplies.
func ScopesContains(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
		for _, implied := range scopeImplies[s] {
			if implied == want {
				return true
			}
		}
	}
	return false
}
