package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newAdminTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedTenant(t *testing.T, s *Store, ctx context.Context, id, handle, did string) {
	t.Helper()
	if err := s.CreateTenant(ctx, &Tenant{ID: id, Handle: handle, DIDMethod: "web", DID: did, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
}

func seedUser(t *testing.T, s *Store, ctx context.Context, id, tenantID, handle string) {
	t.Helper()
	if err := s.CreateUser(ctx, &User{ID: id, TenantID: tenantID, Handle: handle, DisplayName: "orig", Email: handle + "@x.test", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

func TestSetUserDisplayName(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")

	if err := s.SetUserDisplayName(ctx, "u1", "Alice Smith"); err != nil {
		t.Fatalf("SetUserDisplayName: %v", err)
	}
	u, err := s.UserByID(ctx, "u1")
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if u.DisplayName != "Alice Smith" {
		t.Fatalf("display_name = %q, want %q", u.DisplayName, "Alice Smith")
	}
	if err := s.SetUserDisplayName(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}

func TestUpdateProfileLink(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")
	must(t, s.UpsertProfilePage(ctx, &ProfilePage{ID: "pp1", TenantID: "t1", AccountID: "u1", DisplayName: "alice", Theme: "default", UpdatedAt: time.Now()}))
	must(t, s.AddProfileLink(ctx, &ProfileLink{ID: "l1", ProfilePageID: "pp1", Position: 0, Kind: "url", Label: "old", URL: "https://old.test", IsVisible: true, CreatedAt: time.Now()}))

	upd := &ProfileLink{ID: "l1", ProfilePageID: "pp1", Position: 2, Kind: "email", BrandKey: "bk", Label: "new", URL: "mailto:a@b.test", IconBlobKey: "ic", IsVisible: false}
	must(t, s.UpdateProfileLink(ctx, "pp1", "l1", upd))
	links, err := s.ListProfileLinks(ctx, "pp1")
	if err != nil {
		t.Fatalf("ListProfileLinks: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("len = %d, want 1", len(links))
	}
	got := links[0]
	if got.Label != "new" || got.URL != "mailto:a@b.test" || got.Position != 2 || got.Kind != "email" || got.BrandKey != "bk" || got.IconBlobKey != "ic" || got.IsVisible {
		t.Fatalf("link = %+v, want updated fields", got)
	}
	// Wrong profile page scope -> not found.
	if err := s.UpdateProfileLink(ctx, "pp-other", "l1", upd); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong page = %v, want ErrNotFound", err)
	}
}

func TestDeleteWebAuthnCredential(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")

	cred1 := []byte("cred-1")
	cred2 := []byte("cred-2")
	if err := s.AddWebAuthnCredential(ctx, &WebAuthnCredential{ID: "c1", UserID: "u1", CredentialID: cred1, PublicKey: []byte("pk1"), Data: []byte("d1"), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}
	if err := s.AddWebAuthnCredential(ctx, &WebAuthnCredential{ID: "c2", UserID: "u1", CredentialID: cred2, PublicKey: []byte("pk2"), Data: []byte("d2"), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}

	// Deleting one of two succeeds.
	if err := s.DeleteWebAuthnCredential(ctx, "u1", cred1); err != nil {
		t.Fatalf("DeleteWebAuthnCredential: %v", err)
	}
	creds, err := s.ListWebAuthnCredentials(ctx, "u1")
	if err != nil {
		t.Fatalf("ListWebAuthnCredentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("len = %d, want 1", len(creds))
	}

	// Deleting the last credential is refused.
	if err := s.DeleteWebAuthnCredential(ctx, "u1", cred2); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("last = %v, want ErrLastCredential", err)
	}
	// Still present.
	if _, err := s.GetWebAuthnCredential(ctx, cred2); err != nil {
		t.Fatalf("cred2 should remain: %v", err)
	}
	// Deleting a nonexistent credential for a user with none -> not found.
	if err := s.DeleteWebAuthnCredential(ctx, "u1", []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("none = %v, want ErrNotFound", err)
	}
}

func TestGetTenantByIDAndDID(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:example.com")

	byID, err := s.GetTenantByID(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenantByID: %v", err)
	}
	if byID.Handle != "t1" || byID.DID != "did:web:example.com" {
		t.Fatalf("tenant = %+v", byID)
	}
	if _, err := s.GetTenantByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id = %v, want ErrNotFound", err)
	}

	byDID, err := s.GetTenantByDID(ctx, "did:web:example.com")
	if err != nil {
		t.Fatalf("GetTenantByDID: %v", err)
	}
	if byDID.ID != "t1" {
		t.Fatalf("did tenant id = %q, want t1", byDID.ID)
	}
	if _, err := s.GetTenantByDID(ctx, "did:web:nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing did = %v, want ErrNotFound", err)
	}
}

func TestListUsersPage(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedTenant(t, s, ctx, "t2", "t2", "did:web:t2")
	for i := 0; i < 5; i++ {
		seedUser(t, s, ctx, "u"+string(rune('a'+i)), "t1", "u"+string(rune('a'+i)))
	}
	seedUser(t, s, ctx, "other", "t2", "other")

	page1, total, err := s.ListUsersPage(ctx, "t1", 2, 0)
	if err != nil {
		t.Fatalf("ListUsersPage: %v", err)
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5", total)
	}
	if len(page1) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page1))
	}
	page2, _, err := s.ListUsersPage(ctx, "t1", 2, 2)
	if err != nil {
		t.Fatalf("ListUsersPage: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2 len = %d, want 2", len(page2))
	}
	// No cross-tenant leak.
	for _, u := range append(page1, page2...) {
		if u.TenantID != "t1" {
			t.Fatalf("leaked user %+v", u)
		}
	}
	// Empty tenant.
	empty, total, err := s.ListUsersPage(ctx, "t-none", 10, 0)
	if err != nil {
		t.Fatalf("ListUsersPage empty: %v", err)
	}
	if len(empty) != 0 || total != 0 {
		t.Fatalf("empty = %d/%d, want 0/0", len(empty), total)
	}
}

func TestListAuditPage(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	for i := 0; i < 4; i++ {
		if err := s.AppendAudit(ctx, &AuditEntry{ID: "a" + string(rune('0'+i)), TenantID: "t1", Actor: "u1", Action: "act", CreatedAt: time.Now().Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	page, total, err := s.ListAuditPage(ctx, "t1", 2, 0)
	if err != nil {
		t.Fatalf("ListAuditPage: %v", err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if len(page) != 2 {
		t.Fatalf("len = %d, want 2", len(page))
	}
	// Newest first.
	if page[0].ID != "a3" {
		t.Fatalf("page[0] = %q, want a3 (newest first)", page[0].ID)
	}
	// Cross-tenant isolation.
	if _, total, err := s.ListAuditPage(ctx, "t-other", 10, 0); err != nil || total != 0 {
		t.Fatalf("other tenant = %d, %v; want 0, nil", total, err)
	}
}

func TestListClientsPage(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.CreateClient(ctx, &Client{ID: "c" + string(rune('0'+i)), Secret: "secret", RedirectURIs: []string{"https://x"}, Scopes: []string{"openid"}, CreatedAt: time.Now()}); err != nil {
			t.Fatalf("CreateClient: %v", err)
		}
	}
	page, total, err := s.ListClientsPage(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListClientsPage: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if len(page) != 2 {
		t.Fatalf("len = %d, want 2", len(page))
	}
}

func TestListTenantsPage(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		seedTenant(t, s, ctx, "t"+string(rune('0'+i)), "t"+string(rune('0'+i)), "did:web:t"+string(rune('0'+i)))
	}
	page, total, err := s.ListTenantsPage(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListTenantsPage: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if len(page) != 2 {
		t.Fatalf("len = %d, want 2", len(page))
	}
}

func TestCountUsers(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedTenant(t, s, ctx, "t2", "t2", "did:web:t2")
	seedUser(t, s, ctx, "u1", "t1", "a")
	seedUser(t, s, ctx, "u2", "t1", "b")
	seedUser(t, s, ctx, "u3", "t2", "c")

	n, err := s.CountUsers(ctx, "t1")
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if n != 2 {
		t.Fatalf("t1 count = %d, want 2", n)
	}
	n, err = s.CountUsers(ctx, "t-none")
	if err != nil {
		t.Fatalf("CountUsers empty: %v", err)
	}
	if n != 0 {
		t.Fatalf("empty count = %d, want 0", n)
	}
}

func TestDeleteUserCascade(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")

	// Populate every related table.
	must(t, s.AddWebAuthnCredential(ctx, &WebAuthnCredential{ID: "c1", UserID: "u1", CredentialID: []byte("cred"), PublicKey: []byte("pk"), Data: []byte("d"), CreatedAt: time.Now()}))
	must(t, s.CreatePublicKey(ctx, &PublicKey{ID: "k1", TenantID: "t1", AccountID: "u1", KeyType: "ssh", Fingerprint: "fp", KeyMaterial: "ssh-ed25519 AAAA", CreatedAt: time.Now()}))
	must(t, s.CreateProofClaim(ctx, &ProofClaim{ID: "pc1", TenantID: "t1", AccountID: "u1", AnchorType: "dns", AnchorValue: "x", Service: "s", ClaimLocation: "l", ExpectedToken: "t", Status: "pending", CreatedAt: time.Now()}))
	must(t, s.UpsertProfilePage(ctx, &ProfilePage{ID: "pp1", TenantID: "t1", AccountID: "u1", DisplayName: "alice", Theme: "default", UpdatedAt: time.Now()}))
	must(t, s.AddProfileLink(ctx, &ProfileLink{ID: "l1", ProfilePageID: "pp1", Position: 0, Kind: "url", Label: "x", URL: "https://x", IsVisible: true, CreatedAt: time.Now()}))
	must(t, s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{Token: "tok", Subject: "u1", ClientID: "c", Scopes: "openid", AuthTime: time.Now(), CreatedAt: time.Now()}))
	must(t, s.CreateInviteToken(ctx, &InviteToken{ID: "it1", TokenHash: "hash", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}))

	must(t, s.DeleteUser(ctx, "u1"))

	// User gone.
	if _, err := s.UserByID(ctx, "u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user = %v, want ErrNotFound", err)
	}
	// Credentials gone.
	if creds, _ := s.ListWebAuthnCredentials(ctx, "u1"); len(creds) != 0 {
		t.Fatalf("credentials remain: %d", len(creds))
	}
	// Keys gone.
	if keys, _ := s.ListPublicKeys(ctx, "t1", ""); len(keys) != 0 {
		t.Fatalf("keys remain: %d", len(keys))
	}
	// Proofs gone.
	if proofs, _ := s.ListProofClaims(ctx, "t1"); len(proofs) != 0 {
		t.Fatalf("proofs remain: %d", len(proofs))
	}
	// Profile page gone (and its links via FK cascade).
	if _, err := s.GetProfilePage(ctx, "t1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("profile page = %v, want ErrNotFound", err)
	}
	// Refresh token gone.
	if _, err := s.GetAuthRefreshToken(ctx, "tok"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("refresh token = %v, want ErrNotFound", err)
	}
	// Invite token gone.
	if _, err := s.InviteTokenByHash(ctx, "hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invite token = %v, want ErrNotFound", err)
	}
	// Deleting a nonexistent user -> not found.
	if err := s.DeleteUser(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}
