package wiring

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/authstore"
	"github.com/selfagency/sovereign/internal/protocols/solid"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// testIssuer and testAudience are the expected iss/aud used across the wiring
// tests.
const (
	testIssuer   = "https://id.example.com"
	testAudience = "example.com"
)

// newTestStores opens temp SQLite + auth stores.
func newTestStores(t *testing.T) (st *store.Store, as *authstore.Store) {
	t.Helper()
	var err error
	st, err = store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mem, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	as, err = authstore.New(context.Background(), mem, st)
	if err != nil {
		t.Fatal(err)
	}
	return st, as
}

// mintAccessToken signs a short-lived access token for the given subject and
// scopes using the auth store's signing key.
func mintAccessToken(t *testing.T, as *authstore.Store, subject string, scopes []string) string {
	t.Helper()
	tok, err := auth.MintAccessToken(as.SigningKey(), subject, scopes, auth.AccessTokenTTL, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	return tok
}

// TestTokenValidatorRejectsRefreshToken verifies a refresh token is NOT
// accepted as a bearer access token at resource endpoints. Token-type
// separation: refresh tokens are only valid at the OIDC token endpoint.
func TestTokenValidatorRejectsRefreshToken(t *testing.T) {
	_, as := newTestStores(t)
	ctx := context.Background()
	_ = as.PersistRefreshToken(ctx, "refresh-tok", "alice", "client1", []string{"rw"})

	v := &TokenValidator{Key: as.SigningKey(), Issuer: testIssuer, Audience: testAudience}
	if _, err := v.ValidateToken(ctx, "refresh-tok"); err == nil {
		t.Fatal("refresh token accepted as access token — token-type separation violated")
	}
}

// TestTokenValidatorValid verifies a valid access token returns scopes.
func TestTokenValidatorValid(t *testing.T) {
	_, as := newTestStores(t)
	ctx := context.Background()
	tok := mintAccessToken(t, as, "alice", []string{"openid", "profile"})

	v := &TokenValidator{Key: as.SigningKey(), Issuer: testIssuer, Audience: testAudience}
	scopes, err := v.ValidateToken(ctx, tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("scopes = %v, want 2", scopes)
	}
}

// TestTokenValidatorInvalid verifies an invalid token errors.
func TestTokenValidatorInvalid(t *testing.T) {
	_, as := newTestStores(t)
	v := &TokenValidator{Key: as.SigningKey(), Issuer: testIssuer, Audience: testAudience}
	if _, err := v.ValidateToken(context.Background(), "bad"); err == nil {
		t.Fatal("expected error for invalid token")
	}
	if _, err := v.ValidateToken(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

// TestACLChecker verifies read/write authorization.
func TestACLChecker(t *testing.T) {
	st, _ := newTestStores(t)
	a := &ACLChecker{Store: st}
	ctx := context.Background()

	// Public agent can read.
	if !a.CanRead(ctx, "docs/x", solid.PublicAgent) {
		t.Fatal("public agent should read")
	}
	// Public agent cannot write.
	if a.CanWrite(ctx, "docs/x", solid.PublicAgent) {
		t.Fatal("public agent should not write")
	}
	// Without a tenant context, no authenticated agent can write (ownership
	// cannot be established).
	if a.CanWrite(ctx, "docs/x", solid.Agent{WebID: "https://alice.example.com/profile/card#me"}) {
		t.Fatal("agent without tenant context should not write")
	}
}

// TestACLCheckerOwnership verifies write access requires the agent's WebID to
// resolve to an account in the resource's tenant (S2). A foreign WebID must
// not be able to write.
func TestACLCheckerOwnership(t *testing.T) {
	st, _ := newTestStores(t)
	ctx := context.Background()

	// Seed a tenant and an account owned by alice.
	if err := st.CreateTenant(ctx, &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAccount(ctx, &store.Account{
		ID: "a1", TenantID: "t1", DID: "did:web:alice.example.com",
		WebID: "https://alice.example.com/profile/card#me",
	}); err != nil {
		t.Fatal(err)
	}

	// A request context carrying tenant t1.
	ctx = tenant.WithTenant(ctx, &tenant.Tenant{ID: "t1", Handle: "alice.example.com"})
	a := &ACLChecker{Store: st}

	// Alice (owner) can write.
	if !a.CanWrite(ctx, "docs/x", solid.Agent{WebID: "https://alice.example.com/profile/card#me"}) {
		t.Fatal("owner should write")
	}
	// A foreign WebID (not in tenant t1) cannot write.
	if a.CanWrite(ctx, "docs/x", solid.Agent{WebID: "https://bob.example.com/profile/card#me"}) {
		t.Fatal("foreign WebID should not write")
	}
	// An unknown WebID cannot write.
	if a.CanWrite(ctx, "docs/x", solid.Agent{WebID: "https://unknown.example.com/profile#me"}) {
		t.Fatal("unknown WebID should not write")
	}
}

// TestScopesContains verifies exact-match scope matching and the explicit
// implication table. Prefix matching is intentionally NOT supported.
func TestScopesContains(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   string
		ok     bool
	}{
		{"exact match", []string{"profile:read"}, "profile:read", true},
		{"exact match among several", []string{"self", "profile:read"}, "profile:read", true},
		{"read-only does not imply read", []string{"profile:read-only"}, "profile:read", false},
		{"readx does not imply read", []string{"self:readx"}, "self:read", false},
		{"r does not imply rw", []string{"r"}, "rw", false},
		{"empty scopes", nil, "profile:read", false},
		{"empty want", []string{"profile:read"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopesContains(tt.scopes, tt.want); got != tt.ok {
				t.Fatalf("ScopesContains(%v, %q) = %v, want %v", tt.scopes, tt.want, got, tt.ok)
			}
		})
	}
}

// TestScopeImplies verifies the implication table drives hierarchical matching
// and that no prefix logic leaks in.
func TestScopeImplies(t *testing.T) {
	// A granted scope satisfies itself via exact match.
	if !ScopesContains([]string{"profile:write"}, "profile:write") {
		t.Fatal("exact match should hold")
	}
	// A granted scope never satisfies a longer scope via prefix.
	if ScopesContains([]string{"profile:write"}, "profile:write:extra") {
		t.Fatal("prefix must not imply longer scope")
	}
	// Every implication in the table must actually be honored.
	for granted, implied := range scopeImplies {
		for _, w := range implied {
			if !ScopesContains([]string{granted}, w) {
				t.Fatalf("scopeImplies[%q] should satisfy %q", granted, w)
			}
		}
	}
}

// TestSubjectValidatorValid verifies a valid access token returns the subject.
func TestSubjectValidatorValid(t *testing.T) {
	_, as := newTestStores(t)
	ctx := context.Background()
	tok := mintAccessToken(t, as, "alice", []string{"rw"})

	v := &SubjectValidator{Key: as.SigningKey(), Issuer: testIssuer, Audience: testAudience}
	subject, err := v.ValidateToken(ctx, tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if subject != "alice" {
		t.Fatalf("subject = %q, want alice", subject)
	}
}

// TestSubjectValidatorInvalid verifies invalid/empty tokens error.
func TestSubjectValidatorInvalid(t *testing.T) {
	_, as := newTestStores(t)
	v := &SubjectValidator{Key: as.SigningKey(), Issuer: testIssuer, Audience: testAudience}
	if _, err := v.ValidateToken(context.Background(), "bad"); err == nil {
		t.Fatal("expected error for invalid token")
	}
	if _, err := v.ValidateToken(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

// TestSubjectValidatorWebIDClaim proves the webid claim takes precedence over
// sub for the Solid agent identity (Solid-OIDC).
func TestSubjectValidatorWebIDClaim(t *testing.T) {
	_, as := newTestStores(t)
	ctx := context.Background()
	tok, err := auth.MintAccessTokenWebID(as.SigningKey(), "alice", "https://alice.example.com/profile#me", []string{"openid"}, auth.AccessTokenTTL, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}

	v := &SubjectValidator{Key: as.SigningKey(), Issuer: testIssuer, Audience: testAudience}
	subject, err := v.ValidateToken(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "https://alice.example.com/profile#me" {
		t.Fatalf("subject = %q, want the webid claim", subject)
	}
}

// TestSubjectValidatorSubFallback proves a token without a webid claim falls
// back to sub.
func TestSubjectValidatorSubFallback(t *testing.T) {
	_, as := newTestStores(t)
	ctx := context.Background()
	tok := mintAccessToken(t, as, "alice", []string{"openid"})

	v := &SubjectValidator{Key: as.SigningKey(), Issuer: testIssuer, Audience: testAudience}
	subject, err := v.ValidateToken(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "alice" {
		t.Fatalf("subject = %q, want alice (sub fallback)", subject)
	}
}
