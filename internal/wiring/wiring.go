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
	// Coarse admin scopes (granted to cookie/browser admin principals from the
	// user record) imply their granular read/write variants declared on the
	// admin routes. Without these, a cookie admin holding only the coarse
	// scope is 403 on every granular admin route.
	"admin:tenants":    {"admin:tenants:read", "admin:tenants:write"},
	"admin:users":      {"admin:users:read", "admin:users:write"},
	"admin:clients":    {"admin:clients:read", "admin:clients:write"},
	"admin:backup":     {"admin:backup:read", "admin:backup:write"},
	"admin:moderation": {"admin:moderation:read", "admin:moderation:write"},
	"admin:audit":      {"admin:audit:read"},
	"admin:ipfs":       {"admin:ipfs:read", "admin:ipfs:write"},
	"admin:system":     {"admin:system:read", "admin:system:write"},
	// Coarse self-service scopes (granted to cookie principals) imply their
	// granular variants declared on the /me/* routes.
	"self":        {"self:read", "self:write"},
	"profile":     {"profile:read", "profile:write", "profile:publish"},
	"keys":        {"keys:read", "keys:write"},
	"proofs":      {"proofs:read", "proofs:write", "proofs:verify"},
	"sessions":    {"sessions:read", "sessions:revoke"},
	"tokens":      {"tokens:read", "tokens:write", "tokens:revoke"},
	"credentials": {"credentials:read", "credentials:write"},
	"export":      {"export:read"},
	"account":     {"account:delete"},
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
