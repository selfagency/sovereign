package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newTestStore opens an in-memory SQLite store.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestPublicKeyCRUD verifies create/list/get/revoke/delete.
func TestPublicKeyCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	k := PublicKey{
		ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "ssh",
		Fingerprint: "fp1", KeyMaterial: "ssh-ed25519 AAAA", Algorithm: "ssh-ed25519",
	}
	if err := s.CreatePublicKey(ctx, &k); err != nil {
		t.Fatalf("CreatePublicKey: %v", err)
	}

	// Duplicate fingerprint rejected.
	if err := s.CreatePublicKey(ctx, &k); !errors.Is(err, ErrDuplicateFingerprint) {
		t.Fatalf("duplicate = %v, want ErrDuplicateFingerprint", err)
	}

	// List.
	keys, err := s.ListPublicKeys(ctx, "t1", "")
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListPublicKeys = %d, %v", len(keys), err)
	}

	// Get.
	got, err := s.GetPublicKey(ctx, "t1", "k1")
	if err != nil || got.Fingerprint != "fp1" {
		t.Fatalf("GetPublicKey = %+v, %v", got, err)
	}

	// Revoke.
	if err := s.RevokePublicKey(ctx, "t1", "a1", "k1"); err != nil {
		t.Fatalf("RevokePublicKey: %v", err)
	}
	got, _ = s.GetPublicKey(ctx, "t1", "k1")
	if got.RevokedAt == nil {
		t.Fatal("key should be revoked")
	}

	// Delete.
	if err := s.DeletePublicKey(ctx, "t1", "a1", "k1"); err != nil {
		t.Fatalf("DeletePublicKey: %v", err)
	}
	if _, err := s.GetPublicKey(ctx, "t1", "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

// TestPublicKeyOwnership verifies cross-account operations are rejected.
func TestPublicKeyOwnership(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.CreatePublicKey(ctx, &PublicKey{ID: "k1", TenantID: "t1", AccountID: "a1", KeyType: "ssh", Fingerprint: "fp1", KeyMaterial: "x"})

	// Wrong account cannot revoke.
	if err := s.RevokePublicKey(ctx, "t1", "a2", "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-account revoke = %v, want ErrNotFound", err)
	}
	// Wrong tenant cannot get.
	if _, err := s.GetPublicKey(ctx, "t2", "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get = %v, want ErrNotFound", err)
	}
}

// TestProfilePageUpsert verifies upsert + get.
func TestProfilePageUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	p := ProfilePage{ID: "p1", TenantID: "t1", AccountID: "a1", DisplayName: "Alice", Theme: "default", IsPublished: true, UpdatedAt: time.Now()}
	if err := s.UpsertProfilePage(ctx, &p); err != nil {
		t.Fatalf("UpsertProfilePage: %v", err)
	}

	// Upsert updates.
	p.DisplayName = "Alice Updated"
	if err := s.UpsertProfilePage(ctx, &p); err != nil {
		t.Fatalf("UpsertProfilePage: %v", err)
	}
	got, err := s.GetProfilePage(ctx, "t1")
	if err != nil || got.DisplayName != "Alice Updated" {
		t.Fatalf("GetProfilePage = %+v, %v", got, err)
	}
}

// TestProfileLinks verifies add/list/reorder/delete + cascade.
func TestProfileLinks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &ProfilePage{ID: "p1", TenantID: "t1", AccountID: "a1", UpdatedAt: time.Now()})

	_ = s.AddProfileLink(ctx, &ProfileLink{ID: "l1", ProfilePageID: "p1", Position: 0, Kind: "custom", Label: "Site", URL: "https://example.com", CreatedAt: time.Now()})
	_ = s.AddProfileLink(ctx, &ProfileLink{ID: "l2", ProfilePageID: "p1", Position: 1, Kind: "custom", Label: "Blog", URL: "https://blog.example.com", CreatedAt: time.Now()})

	links, err := s.ListProfileLinks(ctx, "p1")
	if err != nil || len(links) != 2 {
		t.Fatalf("ListProfileLinks = %d, %v", len(links), err)
	}

	// Reorder atomically.
	if err := s.ReorderProfileLinks(ctx, "p1", []string{"l2", "l1"}); err != nil {
		t.Fatalf("ReorderProfileLinks: %v", err)
	}
	links, _ = s.ListProfileLinks(ctx, "p1")
	if links[0].ID != "l2" {
		t.Fatalf("reorder failed: first = %s", links[0].ID)
	}

	// Delete page cascades to links.
	if err := s.DeleteProfilePage(ctx, "t1"); err != nil {
		t.Fatalf("DeleteProfilePage: %v", err)
	}
	links, _ = s.ListProfileLinks(ctx, "p1")
	if len(links) != 0 {
		t.Fatalf("cascade delete left %d links", len(links))
	}
}

// TestDeleteProfileLink verifies deleting a single link.
func TestDeleteProfileLink(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &ProfilePage{ID: "p1", TenantID: "t1", AccountID: "a1", UpdatedAt: time.Now()})
	_ = s.AddProfileLink(ctx, &ProfileLink{ID: "l1", ProfilePageID: "p1", Position: 0, Kind: "custom", Label: "Site", URL: "https://example.com", CreatedAt: time.Now()})

	if err := s.DeleteProfileLink(ctx, "p1", "l1"); err != nil {
		t.Fatalf("DeleteProfileLink: %v", err)
	}
	links, _ := s.ListProfileLinks(ctx, "p1")
	if len(links) != 0 {
		t.Fatalf("after delete = %d links", len(links))
	}
	// Missing link -> ErrNotFound.
	if err := s.DeleteProfileLink(ctx, "p1", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}

// TestProofClaimCRUD verifies claim create/list/update/delete.
func TestProofClaimCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	c := ProofClaim{
		ID: "c1", TenantID: "t1", AccountID: "a1", AnchorType: "did", AnchorValue: "did:plc:x",
		Service: "dns", ClaimLocation: "_atproto.example.com", ExpectedToken: "did:plc:x", Status: "pending", CreatedAt: time.Now(),
	}
	if err := s.CreateProofClaim(ctx, &c); err != nil {
		t.Fatalf("CreateProofClaim: %v", err)
	}

	// Duplicate rejected.
	if err := s.CreateProofClaim(ctx, &c); !errors.Is(err, ErrDuplicateClaim) {
		t.Fatalf("duplicate = %v, want ErrDuplicateClaim", err)
	}

	// Update status.
	if err := s.UpdateProofClaimStatus(ctx, "t1", "c1", "verified", ""); err != nil {
		t.Fatalf("UpdateProofClaimStatus: %v", err)
	}

	// Verified list.
	verified, err := s.VerifiedProofClaims(ctx, "t1")
	if err != nil || len(verified) != 1 || verified[0].Status != "verified" {
		t.Fatalf("VerifiedProofClaims = %d, %v", len(verified), err)
	}

	// Delete.
	if err := s.DeleteProofClaim(ctx, "t1", "a1", "c1"); err != nil {
		t.Fatalf("DeleteProofClaim: %v", err)
	}
	claims, _ := s.ListProofClaims(ctx, "t1")
	if len(claims) != 0 {
		t.Fatalf("after delete = %d claims", len(claims))
	}
}

// TestGetProofClaim verifies fetching a single claim by id, scoped to tenant,
// and that a missing claim returns ErrNotFound.
func TestGetProofClaim(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	c := ProofClaim{
		ID: "c1", TenantID: "t1", AccountID: "a1", AnchorType: "did", AnchorValue: "did:plc:x",
		Service: "dns", ClaimLocation: "_atproto.example.com", ExpectedToken: "did:plc:x", Status: "pending", CreatedAt: time.Now(),
	}
	if err := s.CreateProofClaim(ctx, &c); err != nil {
		t.Fatalf("CreateProofClaim: %v", err)
	}

	got, err := s.GetProofClaim(ctx, "t1", "c1")
	if err != nil {
		t.Fatalf("GetProofClaim: %v", err)
	}
	if got.ID != "c1" || got.TenantID != "t1" || got.Status != "pending" {
		t.Fatalf("GetProofClaim = %+v", got)
	}

	// Missing claim -> ErrNotFound.
	if _, err := s.GetProofClaim(ctx, "t1", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	// Wrong tenant -> ErrNotFound (isolation).
	if _, err := s.GetProofClaim(ctx, "t2", "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant = %v, want ErrNotFound", err)
	}
}

// TestProofClaimListEmpty verifies listing with no claims returns empty.
func TestProofClaimListEmpty(t *testing.T) {
	s := newTestStore(t)
	claims, err := s.ListProofClaims(context.Background(), "t1")
	if err != nil || len(claims) != 0 {
		t.Fatalf("ListProofClaims = %d, %v, want empty", len(claims), err)
	}
}

// TestProofClaimUpdateMissing verifies updating a missing claim errors.
func TestProofClaimUpdateMissing(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpdateProofClaimStatus(context.Background(), "t1", "missing", "verified", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update = %v, want ErrNotFound", err)
	}
}

// TestProofClaimDeleteMissing verifies deleting a missing claim errors.
func TestProofClaimDeleteMissing(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteProofClaim(context.Background(), "t1", "a1", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete = %v, want ErrNotFound", err)
	}
}

// TestRevokeMissingKey verifies revoking a missing key errors.
func TestRevokeMissingKey(t *testing.T) {
	s := newTestStore(t)
	if err := s.RevokePublicKey(context.Background(), "t1", "a1", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing revoke = %v, want ErrNotFound", err)
	}
}

// TestDeleteMissingKey verifies deleting a missing key errors.
func TestDeleteMissingKey(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeletePublicKey(context.Background(), "t1", "a1", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete = %v, want ErrNotFound", err)
	}
}

// TestSQLitePoolLimitSet verifies Open configures an explicit connection pool
// limit. It fails if the limit is removed, because busy_timeout(5000) in the
// DSN may otherwise let concurrent writes succeed without it.
func TestSQLitePoolLimitSet(t *testing.T) {
	s := newTestStore(t)
	if got := s.db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}
}

// TestSQLiteConcurrentWrites verifies N goroutines can write distinct rows
// concurrently without hitting 'database is locked'.
func TestSQLiteConcurrentWrites(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.CreateTenant(ctx, &Tenant{
				ID:     fmt.Sprintf("t%d", i),
				Handle: fmt.Sprintf("alice%d.example.com", i),
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	// All rows must be present.
	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != n {
		t.Fatalf("ListTenants = %d rows, want %d", len(tenants), n)
	}
}

// TestOpenInvalidPath verifies opening an invalid path errors.
func TestOpenInvalidPath(t *testing.T) {
	if _, err := Open("/nonexistent-dir/test.db"); err == nil {
		t.Fatal("expected error for invalid path")
	}
}

// TestOpenFilePermissions verifies the DB file is owner-only (0600) and the
// data directory is 0700, so the signing key and token hashes are not
// world-readable.
func TestOpenFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("db perms = %o, want 600", perm)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir perms = %o, want 700", perm)
	}
}

// TestTenantCRUD verifies tenant create/get/list/delete.
func TestTenantCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_ = s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	// Duplicate handle rejected.
	if err := s.CreateTenant(ctx, &Tenant{ID: "t2", Handle: "alice.example.com"}); !errors.Is(err, ErrDuplicateTenant) {
		t.Fatalf("duplicate = %v, want ErrDuplicateTenant", err)
	}

	// Get by handle.
	got, err := s.GetTenantByHandle(ctx, "alice.example.com")
	if err != nil || got.ID != "t1" {
		t.Fatalf("GetTenantByHandle = %+v, %v", got, err)
	}

	// Missing -> ErrNotFound.
	if _, err := s.GetTenantByHandle(ctx, "missing.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}

	// List.
	tenants, err := s.ListTenants(ctx)
	if err != nil || len(tenants) != 1 {
		t.Fatalf("ListTenants = %d, %v", len(tenants), err)
	}

	// Delete.
	if err := s.DeleteTenant(ctx, "alice.example.com"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, err := s.GetTenantByHandle(ctx, "alice.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

// TestDeleteTenantMissing verifies deleting a missing tenant errors.
func TestDeleteTenantMissing(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteTenant(context.Background(), "missing.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete = %v, want ErrNotFound", err)
	}
}
