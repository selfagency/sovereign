package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newAuthTestStore opens a temp SQLite store.
func newAuthTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestAuthSigningKeyCRUD verifies signing key save/get.
func TestAuthSigningKeyCRUD(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()

	k := AuthSigningKey{ID: "signing-1", KeyPEM: "test-key-material", CreatedAt: time.Now()}
	if err := s.SaveAuthSigningKey(ctx, k); err != nil {
		t.Fatalf("SaveAuthSigningKey: %v", err)
	}
	got, err := s.GetAuthSigningKey(ctx, "signing-1")
	if err != nil {
		t.Fatalf("GetAuthSigningKey: %v", err)
	}
	if got.KeyPEM != k.KeyPEM {
		t.Fatalf("key_pem = %q, want %q", got.KeyPEM, k.KeyPEM)
	}
	if _, err := s.GetAuthSigningKey(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}

// TestAuthSigningKeyUpsert verifies save is idempotent by ID.
func TestAuthSigningKeyUpsert(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()
	_ = s.SaveAuthSigningKey(ctx, AuthSigningKey{ID: "signing-1", KeyPEM: "key1", CreatedAt: time.Now()})
	_ = s.SaveAuthSigningKey(ctx, AuthSigningKey{ID: "signing-1", KeyPEM: "key2", CreatedAt: time.Now()})
	got, _ := s.GetAuthSigningKey(ctx, "signing-1")
	if got.KeyPEM != "key2" {
		t.Fatalf("key_pem = %q, want key2 (upsert)", got.KeyPEM)
	}
}

// TestAuthRefreshTokenCRUD verifies refresh token save/get/delete.
func TestAuthRefreshTokenCRUD(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()
	tok := &AuthRefreshToken{Token: "tok1", Subject: "alice", ClientID: "client1", Scopes: "openid,profile", AuthTime: time.Now(), CreatedAt: time.Now()}
	if err := s.SaveAuthRefreshToken(ctx, tok); err != nil {
		t.Fatalf("SaveAuthRefreshToken: %v", err)
	}
	got, err := s.GetAuthRefreshToken(ctx, "tok1")
	if err != nil {
		t.Fatalf("GetAuthRefreshToken: %v", err)
	}
	if got.Subject != "alice" || got.ClientID != "client1" || got.Scopes != "openid,profile" {
		t.Fatalf("got = %+v", got)
	}
	if _, err := s.GetAuthRefreshToken(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	if err := s.DeleteAuthRefreshToken(ctx, "tok1"); err != nil {
		t.Fatalf("DeleteAuthRefreshToken: %v", err)
	}
	if _, err := s.GetAuthRefreshToken(ctx, "tok1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

// TestAuthRefreshTokenByHash verifies lookup by hashed value + expiry/revoke.
func TestAuthRefreshTokenByHash(t *testing.T) {
	s := newAuthTestStore(t)
	ctx := context.Background()
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "hash1", Subject: "alice", ClientID: "c1", Scopes: "openid", AuthTime: time.Now(), CreatedAt: time.Now()})
	subj, client, scopes, err := s.GetAuthRefreshTokenByHash(ctx, "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if subj != "alice" || client != "c1" || len(scopes) != 1 || scopes[0] != "openid" {
		t.Fatalf("by hash = %q %q %v", subj, client, scopes)
	}
	// Revoked -> ErrNotFound.
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "rev", Subject: "bob", ClientID: "c1", Scopes: "openid", AuthTime: time.Now(), RevokedAt: time.Now(), CreatedAt: time.Now()})
	if _, _, _, err := s.GetAuthRefreshTokenByHash(ctx, "rev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked = %v, want ErrNotFound", err)
	}
	// Expired -> ErrNotFound.
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "exp", Subject: "bob", ClientID: "c1", Scopes: "openid", AuthTime: time.Now(), ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now()})
	if _, _, _, err := s.GetAuthRefreshTokenByHash(ctx, "exp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired = %v, want ErrNotFound", err)
	}
}

// TestCreateUserFirstIsAdmin verifies the first user becomes the instance
// admin.
func TestCreateUserFirstIsAdmin(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByHandle(ctx, "t1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin {
		t.Fatal("first user should be admin")
	}
}

// TestCreateUserSecondNotAdmin verifies subsequent users are not admin by
// default.
func TestCreateUserSecondNotAdmin(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	if err := s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByHandle(ctx, "t1", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if u.IsAdmin {
		t.Fatal("second user should not be admin by default")
	}
}

// TestSetUserAdmin verifies the admin flag can be toggled.
func TestSetUserAdmin(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	_ = s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob"})
	if err := s.SetUserAdmin(ctx, "u2", true); err != nil {
		t.Fatal(err)
	}
	u, _ := s.UserByID(ctx, "u2")
	if !u.IsAdmin {
		t.Fatal("bob should be admin after SetUserAdmin")
	}
	if err := s.SetUserAdmin(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user = %v, want ErrNotFound", err)
	}
}

// TestCreateUserConcurrentFirstAdmin verifies that concurrent creation of
// the first users yields exactly one admin (atomic first-admin decision).
func TestCreateUserConcurrentFirstAdmin(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = s.CreateUser(ctx, &User{ID: fmt.Sprintf("u%d", i), TenantID: "t1", Handle: fmt.Sprintf("user%d", i)})
		}(i)
	}
	wg.Wait()

	users, err := s.ListUsers(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != n {
		t.Fatalf("users = %d, want %d", len(users), n)
	}
	admins := 0
	for _, u := range users {
		if u.IsAdmin {
			admins++
		}
	}
	if admins != 1 {
		t.Fatalf("admins = %d, want exactly 1", admins)
	}
}

// TestCreateUserTenantScoped verifies the first-admin decision is instance-
// scoped, not per-tenant: a first user in tenant B does not become admin
// when a user already exists in tenant A.
func TestCreateUserTenantScoped(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "tA", Handle: "a.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "tA", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	// First user in tenant B.
	if err := s.CreateTenant(ctx, &Tenant{ID: "tB", Handle: "b.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u2", TenantID: "tB", Handle: "bob"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserByHandle(ctx, "tB", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if got.IsAdmin {
		t.Fatal("first user in tenant B should NOT be admin when a user already exists in tenant A")
	}
}

// TestCreateUserCallerOverridePreserved verifies a non-first user with an
// explicit IsAdmin=true stays admin (caller override preserved).
func TestCreateUserCallerOverridePreserved(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserByID(ctx, "u2")
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsAdmin {
		t.Fatal("second user with explicit IsAdmin=true should stay admin")
	}
}

// TestCreateUserReturnedAdminStatus verifies the returned struct reflects the
// actual DB admin outcome: the first user is admin even when the caller did
// not request it, and a non-first user honors the caller's override.
func TestCreateUserReturnedAdminStatus(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}

	// First user: caller passes IsAdmin=false, but the DB promotes them to
	// admin. The returned struct must reflect the DB outcome (admin).
	first := &User{ID: "u1", TenantID: "t1", Handle: "alice"}
	if err := s.CreateUser(ctx, first); err != nil {
		t.Fatal(err)
	}
	if !first.IsAdmin {
		t.Fatal("returned first user should report IsAdmin=true (DB promoted to admin)")
	}

	// Non-first user with explicit override: stays admin.
	override := &User{ID: "u2", TenantID: "t1", Handle: "bob", IsAdmin: true}
	if err := s.CreateUser(ctx, override); err != nil {
		t.Fatal(err)
	}
	if !override.IsAdmin {
		t.Fatal("returned non-first user with IsAdmin=true should report admin")
	}

	// Non-first user without override: stays non-admin.
	plain := &User{ID: "u3", TenantID: "t1", Handle: "carol"}
	if err := s.CreateUser(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if plain.IsAdmin {
		t.Fatal("returned non-first user without override should report non-admin")
	}
}

// TestRotateAuthRefreshToken verifies rotation succeeds, and fails when the
// old token is missing or already rotated.
func TestRotateAuthRefreshToken(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	now := time.Now()
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "old1", Subject: "alice", ClientID: "c1", Scopes: "openid", AuthTime: now, CreatedAt: now})

	// Success: old token rotated, successor persisted.
	succ := &AuthRefreshToken{Token: "new1", Subject: "alice", ClientID: "c1", Scopes: "openid", AuthTime: now, FamilyID: "fam1", CreatedAt: now}
	if err := s.RotateAuthRefreshToken(ctx, "old1", succ); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	old, err := s.GetAuthRefreshToken(ctx, "old1")
	if err != nil {
		t.Fatal(err)
	}
	if old.RotatedAt.IsZero() {
		t.Fatal("old token not marked rotated")
	}
	if _, err := s.GetAuthRefreshToken(ctx, "new1"); err != nil {
		t.Fatalf("successor not persisted: %v", err)
	}

	// Already rotated: replaying the old token must fail.
	if err := s.RotateAuthRefreshToken(ctx, "old1", succ); err == nil {
		t.Fatal("rotating an already-rotated token should fail")
	}

	// Missing token.
	if err := s.RotateAuthRefreshToken(ctx, "nope", succ); err == nil {
		t.Fatal("rotating a missing token should fail")
	}
}

// TestRevokeAuthRefreshTokenFamily verifies family revocation and the empty-
// family no-op.
func TestRevokeAuthRefreshTokenFamily(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	now := time.Now()
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "t1", Subject: "alice", ClientID: "c1", Scopes: "openid", AuthTime: now, FamilyID: "fam1", CreatedAt: now})
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "t2", Subject: "alice", ClientID: "c1", Scopes: "openid", AuthTime: now, FamilyID: "fam1", CreatedAt: now})
	_ = s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "t3", Subject: "bob", ClientID: "c1", Scopes: "openid", AuthTime: now, FamilyID: "fam2", CreatedAt: now})

	if err := s.RevokeAuthRefreshTokenFamily(ctx, "fam1"); err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	for _, tok := range []string{"t1", "t2"} {
		got, err := s.GetAuthRefreshToken(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		if got.RevokedAt.IsZero() {
			t.Fatalf("token %s not revoked", tok)
		}
	}
	// Unrelated family untouched.
	got, _ := s.GetAuthRefreshToken(ctx, "t3")
	if !got.RevokedAt.IsZero() {
		t.Fatal("token in other family should not be revoked")
	}

	// Empty family is a no-op.
	if err := s.RevokeAuthRefreshTokenFamily(ctx, ""); err != nil {
		t.Fatalf("empty family should be a no-op, got %v", err)
	}
}

// TestDeleteClient verifies a client is removed and a missing client yields
// ErrNotFound.
func TestDeleteClient(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateClient(ctx, &Client{ID: "web", Secret: "secret"}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteClient(ctx, "web"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, err := s.ClientByID(ctx, "web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ClientByID after delete = %v, want ErrNotFound", err)
	}
	// Deleting again -> ErrNotFound.
	if err := s.DeleteClient(ctx, "web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteClient missing = %v, want ErrNotFound", err)
	}
}

// TestSetClientSecret verifies re-registering a client secret hashes it and
// updates the row, and rejects over-length secrets and unknown clients.
func TestSetClientSecret(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateClient(ctx, &Client{ID: "web", Secret: "old-secret"}); err != nil {
		t.Fatal(err)
	}

	if err := s.SetClientSecret(ctx, "web", "new-secret"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	c, err := s.ClientByID(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret == "new-secret" {
		t.Fatal("secret stored in plaintext")
	}
	if !VerifyClientSecret("new-secret", c.Secret) {
		t.Fatal("new secret does not verify")
	}
	if VerifyClientSecret("old-secret", c.Secret) {
		t.Fatal("old secret still verifies after rotation")
	}

	// Over-length secret rejected.
	if err := s.SetClientSecret(ctx, "web", strings.Repeat("x", 129)); err == nil {
		t.Fatal("over-length secret accepted")
	}

	// Unknown client.
	if err := s.SetClientSecret(ctx, "nope", "secret"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown client = %v, want ErrNotFound", err)
	}
}

// TestVerifyClientSecretEdgeCases verifies the sentinel and malformed stored
// values are rejected outright (fail closed).
func TestVerifyClientSecretEdgeCases(t *testing.T) {
	// Sentinel written by migration v5.
	if VerifyClientSecret("anything", invalidatedSecret) {
		t.Fatal("sentinel secret should never verify")
	}
	// Non-argon2id prefix.
	if VerifyClientSecret("x", "$bcrypt$v=2a$salt$hash") {
		t.Fatal("non-argon2id stored value should not verify")
	}
	// Wrong number of parts.
	if VerifyClientSecret("x", "$argon2id$v=19$m=1,t=1,p=1") {
		t.Fatal("malformed stored value should not verify")
	}
	// Unparseable params.
	if VerifyClientSecret("x", "$argon2id$v=19$bogus$c2FsdA==$aGFzaA==") {
		t.Fatal("unparseable params should not verify")
	}
	// Invalid base64 salt.
	if VerifyClientSecret("x", "$argon2id$v=19$m=1,t=1,p=1$!!!$aGFzaA==") {
		t.Fatal("invalid base64 salt should not verify")
	}
	// Invalid base64 hash.
	if VerifyClientSecret("x", "$argon2id$v=19$m=1,t=1,p=1$c2FsdA==$!!!") {
		t.Fatal("invalid base64 hash should not verify")
	}
}

// TestCreateClientDuplicate verifies a duplicate client ID is rejected.
func TestCreateClientDuplicate(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateClient(ctx, &Client{ID: "web", Secret: "s1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, &Client{ID: "web", Secret: "s2"}); !errors.Is(err, ErrDuplicateClient) {
		t.Fatalf("duplicate client = %v, want ErrDuplicateClient", err)
	}
}

// TestCreateUserDuplicate verifies a duplicate tenant+handle is rejected.
func TestCreateUserDuplicate(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	if err := s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "alice"}); !errors.Is(err, ErrDuplicateUser) {
		t.Fatalf("duplicate = %v, want ErrDuplicateUser", err)
	}
}

// TestListUsers verifies listing users for a tenant.
func TestListUsers(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})
	_ = s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob"})
	users, err := s.ListUsers(ctx, "t1")
	if err != nil || len(users) != 2 {
		t.Fatalf("users = %v, %v", users, err)
	}
}

// TestClientCRUD verifies client create + lookup + list. The stored secret is
// an argon2id hash, so lookup returns the hash and verification goes through
// VerifyClientSecret.
func TestClientCRUD(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateClient(ctx, &Client{
		ID: "web", Secret: "s3cret", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid", "profile"},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := s.ClientByID(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret == "s3cret" {
		t.Fatal("client secret stored in plaintext")
	}
	if !VerifyClientSecret("s3cret", c.Secret) {
		t.Fatal("valid secret does not verify against stored hash")
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Fatalf("client = %+v", c)
	}
	if len(c.Scopes) != 2 {
		t.Fatalf("scopes = %v", c.Scopes)
	}
	clients, err := s.ListClients(ctx)
	if err != nil || len(clients) != 1 {
		t.Fatalf("list = %v, %v", clients, err)
	}
	if _, err := s.ClientByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown client = %v, want ErrNotFound", err)
	}
}

// TestClientSecretStoredHashed verifies CreateClient stores an argon2id hash,
// never the plaintext secret, and that the plaintext verifies against it.
func TestClientSecretStoredHashed(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	const secret = "s3cret-value"
	if err := s.CreateClient(ctx, &Client{ID: "web", Secret: secret}); err != nil {
		t.Fatal(err)
	}
	c, err := s.ClientByID(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret == secret {
		t.Fatal("client secret stored in plaintext")
	}
	if !VerifyClientSecret(secret, c.Secret) {
		t.Fatal("stored hash does not verify the original secret")
	}
	if VerifyClientSecret("wrong", c.Secret) {
		t.Fatal("wrong secret verifies against stored hash")
	}
}

// TestClientSecretMaxLength verifies CreateClient rejects secrets longer than
// 128 bytes.
func TestClientSecretMaxLength(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateClient(ctx, &Client{ID: "c1", Secret: strings.Repeat("x", 129)}); err == nil {
		t.Fatal("over-length secret accepted")
	}
	// A 128-byte secret is allowed.
	if err := s.CreateClient(ctx, &Client{ID: "c2", Secret: strings.Repeat("x", 128)}); err != nil {
		t.Fatalf("128-byte secret rejected: %v", err)
	}
}

// TestWebAuthnCredentialCRUD verifies credential add/list/get/update.
func TestWebAuthnCredentialCRUD(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"})

	cred := &WebAuthnCredential{ID: "c1", UserID: "u1", CredentialID: []byte{1, 2, 3}, PublicKey: []byte{4, 5, 6}, SignCount: 1, Data: []byte(`{"id":"c1"}`)}
	if err := s.AddWebAuthnCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWebAuthnCredential(ctx, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" || got.SignCount != 1 || len(got.Data) == 0 {
		t.Fatalf("cred = %+v", got)
	}
	if err := s.UpdateWebAuthnSignCount(ctx, "c1", 7); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.GetWebAuthnCredential(ctx, []byte{1, 2, 3})
	if got2.SignCount != 7 {
		t.Fatalf("sign count = %d, want 7", got2.SignCount)
	}
	list, err := s.ListWebAuthnCredentials(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if _, err := s.GetWebAuthnCredential(ctx, []byte{9, 9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown cred = %v, want ErrNotFound", err)
	}
}

// TestAuditLog verifies append + list (newest first).
func TestAuditLog(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.AppendAudit(ctx, &AuditEntry{ID: "a1", TenantID: "t1", Actor: "alice", Action: "takedown", Target: "bob", Detail: "spam"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(ctx, &AuditEntry{ID: "a2", TenantID: "t1", Actor: "alice", Action: "takedown", Target: "carol", Detail: "abuse"}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListAudit(ctx, "t1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].ID != "a2" {
		t.Fatalf("first = %s, want a2 (newest first)", entries[0].ID)
	}
}

// TestUserOnboardingState verifies email, ToS, and passkey-setup flags.
func TestUserOnboardingState(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	must(t, s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}))
	must(t, s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice", Email: "a@example.com"}))

	// Email round-trips through UserByID.
	u, err := s.UserByID(ctx, "u1")
	must(t, err)
	if u.Email != "a@example.com" {
		t.Fatalf("email = %q, want a@example.com", u.Email)
	}
	if u.ToSAccepted || u.PasskeySetup {
		t.Fatalf("new user should not have accepted ToS or set up passkey")
	}

	// Set email, ToS, passkey flags.
	must(t, s.SetUserEmail(ctx, "u1", "b@example.com"))
	must(t, s.SetToSAccepted(ctx, "u1", true))
	must(t, s.SetPasskeySetup(ctx, "u1", true))
	u2, _ := s.UserByID(ctx, "u1")
	if u2.Email != "b@example.com" || !u2.ToSAccepted || !u2.PasskeySetup {
		t.Fatalf("updated user = %+v", u2)
	}
}

// must fails the test if err is non-nil.
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// mustErrNotFound fails the test unless err is ErrNotFound.
func mustErrNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestUserOnboardingStateUnknownUser verifies setters on a missing user
// return ErrNotFound.
func TestUserOnboardingStateUnknownUser(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.SetUserEmail(ctx, "nope", "x@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown email = %v, want ErrNotFound", err)
	}
}

// TestInviteTokenCRUD verifies invite token create/lookup/consume.
func TestInviteTokenCRUD(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}

	it := &InviteToken{ID: "inv1", TokenHash: "abc123hash", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateInviteToken(ctx, it); err != nil {
		t.Fatal(err)
	}
	got, err := s.InviteTokenByHash(ctx, "abc123hash")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" || !got.UsedAt.IsZero() {
		t.Fatalf("invite = %+v", got)
	}

	if err := s.MarkInviteTokenUsed(ctx, "inv1"); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.InviteTokenByHash(ctx, "abc123hash")
	if got2.UsedAt.IsZero() {
		t.Fatalf("invite not marked used")
	}

	if _, err := s.InviteTokenByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown invite = %v, want ErrNotFound", err)
	}
}

// TestInviteTokenConcurrentRedemption verifies that concurrent redemption of
// the same token yields exactly one success (atomic single-use gate).
func TestInviteTokenConcurrentRedemption(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	hash := "concurrenthash"
	if err := s.CreateInviteToken(ctx, &InviteToken{ID: "inv1", TokenHash: hash, UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	const n = 16
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.RedeemInviteToken(ctx, hash, time.Now())
		}(i)
	}
	wg.Wait()

	var successes int
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
}

// TestRedeemInviteAndCreateSessionAtomic verifies the redeem + session create
// are one transaction (audit C2): a session-insert failure must roll back the
// redeem so the invite stays redeemable. The failure is a duplicate session
// token hash (UNIQUE constraint on sessions.token_hash) — a transient error
// that must not burn the invite.
func TestRedeemInviteAndCreateSessionAtomic(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	hash := "atomichash"
	if err := s.CreateInviteToken(ctx, &InviteToken{ID: "inv1", TokenHash: hash, UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Happy path: redeem + session succeed together.
	sess, err := s.RedeemInviteAndCreateSession(ctx, hash, "tokhash", time.Hour, "", "")
	if err != nil {
		t.Fatalf("redeem+create: %v", err)
	}
	if sess.UserID != "u1" {
		t.Fatalf("session user = %q, want u1", sess.UserID)
	}
	// Invite is consumed.
	if err := s.RedeemInviteToken(ctx, hash, time.Now()); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("second redeem = %v, want ErrInviteUsed", err)
	}

	// Failure path: session insert fails (duplicate token hash) -> redeem
	// rolls back and the invite stays redeemable.
	hash2 := "atomic2hash"
	if err := s.CreateInviteToken(ctx, &InviteToken{ID: "inv2", TokenHash: hash2, UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Pre-insert a session with the same token hash to force the UNIQUE
	// violation on the second insert.
	if _, err := s.CreateSession(ctx, "u1", "duptok", time.Hour, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemInviteAndCreateSession(ctx, hash2, "duptok", time.Hour, "", ""); err == nil {
		t.Fatal("redeem+create with duplicate token hash succeeded, want error")
	}
	// Invite must still be redeemable (rollback preserved it).
	if err := s.RedeemInviteToken(ctx, hash2, time.Now()); err != nil {
		t.Fatalf("redeem after failed create = %v, want success (rollback)", err)
	}
}

// TestRedeemInviteAndCreateSessionClassification verifies the n != 1
// classification paths (used, expired, invalid) map to distinct errors.
func TestRedeemInviteAndCreateSessionClassification(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}

	// Used: redeem once, then redeem again.
	hash := "classhash"
	if err := s.CreateInviteToken(ctx, &InviteToken{ID: "inv1", TokenHash: hash, UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemInviteAndCreateSession(ctx, hash, "tokhash", time.Hour, "", ""); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := s.RedeemInviteAndCreateSession(ctx, hash, "tokhash2", time.Hour, "", ""); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("used invite = %v, want ErrInviteUsed", err)
	}

	// Expired: expires_at in the past.
	hash2 := "classhash2"
	if err := s.CreateInviteToken(ctx, &InviteToken{ID: "inv2", TokenHash: hash2, UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemInviteAndCreateSession(ctx, hash2, "tokhash3", time.Hour, "", ""); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("expired invite = %v, want ErrInviteExpired", err)
	}

	// Invalid: unknown token hash.
	if _, err := s.RedeemInviteAndCreateSession(ctx, "nohash", "tokhash4", time.Hour, "", ""); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("unknown invite = %v, want ErrInviteInvalid", err)
	}
}

// TestInviteTokenErrorClassification verifies used/expired/not-found map to
// distinct classified errors.
func TestInviteTokenErrorClassification(t *testing.T) {
	ctx := context.Background()
	s := newAuthTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}

	// Used.
	if err := s.CreateInviteToken(ctx, &InviteToken{ID: "used", TokenHash: "usedhash", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkInviteTokenUsed(ctx, "used"); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInviteToken(ctx, "usedhash", time.Now()); !errors.Is(err, ErrInviteUsed) {
		t.Fatalf("used = %v, want ErrInviteUsed", err)
	}

	// Expired.
	if err := s.CreateInviteToken(ctx, &InviteToken{ID: "exp", TokenHash: "exphash", UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInviteToken(ctx, "exphash", time.Now()); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("expired = %v, want ErrInviteExpired", err)
	}

	// Not found.
	if err := s.RedeemInviteToken(ctx, "nohash", time.Now()); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("not found = %v, want ErrInviteInvalid", err)
	}
}
