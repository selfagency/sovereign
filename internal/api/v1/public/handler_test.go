// Package public_test exercises the /api/v1/public/* anonymous endpoints.
package public_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	v1public "github.com/selfagency/sovereign/internal/api/v1/public"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedTenant(t *testing.T, s *store.Store, tenantID, handle string) *store.Tenant {
	t.Helper()
	tn := &store.Tenant{ID: tenantID, Handle: handle + ".example.com", DIDMethod: "web"}
	if err := s.CreateTenant(context.Background(), tn); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	return tn
}

func newHandler(s *store.Store) *v1public.Handler {
	return v1public.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// req builds an anonymous request carrying the tenant in context (the tenant
// middleware normally injects it from the Host header).
func req(method, path string, tn *tenant.Tenant) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	if tn != nil {
		r = r.WithContext(tenant.WithTenant(r.Context(), tn))
	}
	return r
}

func do(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v (body %s)", v, err, rec.Body.String())
	}
	return v
}

// seedPublishedProfile creates a tenant with a published profile page plus one
// key and one verified proof claim.
func seedPublishedProfile(t *testing.T, s *store.Store, tenantID, handle string) {
	t.Helper()
	ctx := context.Background()
	seedTenant(t, s, tenantID, handle)
	u := &store.User{ID: "user-" + tenantID, TenantID: tenantID, Handle: handle, DisplayName: handle}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertProfilePage(ctx, &store.ProfilePage{
		ID: "page-" + tenantID, TenantID: tenantID, AccountID: u.ID,
		DisplayName: handle, Bio: "hi", IsPublished: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePublicKey(ctx, &store.PublicKey{
		ID: "key-" + tenantID, TenantID: tenantID, AccountID: u.ID,
		KeyType: "ssh", Label: "laptop", Fingerprint: "fp1",
		KeyMaterial: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProofClaim(ctx, &store.ProofClaim{
		ID: "proof-" + tenantID, TenantID: tenantID, AccountID: u.ID,
		AnchorType: "did", AnchorValue: "did:web:" + handle + ".example.com",
		Service: "github", ClaimLocation: "https://github.com/" + handle,
		Status: "verified",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPublicProfilePublished(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedPublishedProfile(t, s, "t1", "alice")
	tn := &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}

	rec := do(h.Profile, req(http.MethodGet, "/api/v1/public/profile", tn))
	if rec.Code != http.StatusOK {
		t.Fatalf("profile = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	p := decode[dto.ProfilePage](t, rec)
	if p.DisplayName != "alice" || !p.IsPublished {
		t.Fatalf("profile = %+v", p)
	}
}

func TestPublicProfileUnpublished404(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "alice")
	ctx := context.Background()
	u := &store.User{ID: "user-t1", TenantID: "t1", Handle: "alice", DisplayName: "alice"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// Profile exists but is NOT published.
	if err := s.UpsertProfilePage(ctx, &store.ProfilePage{
		ID: "page-t1", TenantID: "t1", AccountID: u.ID,
		DisplayName: "alice", Bio: "hi", IsPublished: false,
	}); err != nil {
		t.Fatal(err)
	}
	tn := &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}

	rec := do(h.Profile, req(http.MethodGet, "/api/v1/public/profile", tn))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unpublished profile = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestPublicProfileNoTenant404(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	// No tenant in context: uniform 404, no enumeration signal.
	rec := do(h.Profile, req(http.MethodGet, "/api/v1/public/profile", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no tenant = %d, want 404", rec.Code)
	}
}

func TestPublicProfileUnknownTenant404(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	// Tenant exists but has no profile page at all: 404, same as unpublished.
	seedTenant(t, s, "t1", "alice")
	tn := &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}
	rec := do(h.Profile, req(http.MethodGet, "/api/v1/public/profile", tn))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no profile = %d, want 404", rec.Code)
	}
}

func TestPublicKeys(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedPublishedProfile(t, s, "t1", "alice")
	tn := &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}

	rec := do(h.Keys, req(http.MethodGet, "/api/v1/public/keys", tn))
	if rec.Code != http.StatusOK {
		t.Fatalf("keys = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	keys := decode[[]dto.PublicKey](t, rec)
	if len(keys) != 1 || keys[0].Fingerprint != "fp1" {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestPublicKeysNoTenant404(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Keys, req(http.MethodGet, "/api/v1/public/keys", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no tenant = %d, want 404", rec.Code)
	}
}

func TestPublicProofs(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedPublishedProfile(t, s, "t1", "alice")
	tn := &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}

	rec := do(h.Proofs, req(http.MethodGet, "/api/v1/public/proofs", tn))
	if rec.Code != http.StatusOK {
		t.Fatalf("proofs = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	proofs := decode[[]dto.ProofClaim](t, rec)
	if len(proofs) != 1 || proofs[0].Status != "verified" {
		t.Fatalf("proofs = %+v", proofs)
	}
}

func TestPublicProofsNoTenant404(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Proofs, req(http.MethodGet, "/api/v1/public/proofs", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no tenant = %d, want 404", rec.Code)
	}
}

// TestPublicProofsOnlyVerified ensures unverified claims are not exposed.
func TestPublicProofsOnlyVerified(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "alice")
	ctx := context.Background()
	u := &store.User{ID: "user-t1", TenantID: "t1", Handle: "alice", DisplayName: "alice"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProofClaim(ctx, &store.ProofClaim{
		ID: "p-pending", TenantID: "t1", AccountID: u.ID,
		AnchorType: "did", AnchorValue: "did:web:alice.example.com",
		Service: "github", ClaimLocation: "https://github.com/alice/pending", Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProofClaim(ctx, &store.ProofClaim{
		ID: "p-verified", TenantID: "t1", AccountID: u.ID,
		AnchorType: "did", AnchorValue: "did:web:alice.example.com",
		Service: "github", ClaimLocation: "https://github.com/alice/verified", Status: "verified",
	}); err != nil {
		t.Fatal(err)
	}
	tn := &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}

	rec := do(h.Proofs, req(http.MethodGet, "/api/v1/public/proofs", tn))
	if rec.Code != http.StatusOK {
		t.Fatalf("proofs = %d, want 200", rec.Code)
	}
	proofs := decode[[]dto.ProofClaim](t, rec)
	if len(proofs) != 1 || proofs[0].ID != "p-verified" {
		t.Fatalf("proofs = %+v, want only verified", proofs)
	}
}

// TestPublicKeysExcludesRevoked ensures revoked keys are not exposed.
func TestPublicKeysExcludesRevoked(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "alice")
	ctx := context.Background()
	u := &store.User{ID: "user-t1", TenantID: "t1", Handle: "alice", DisplayName: "alice"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.CreatePublicKey(ctx, &store.PublicKey{
		ID: "k-active", TenantID: "t1", AccountID: u.ID,
		KeyType: "ssh", Label: "a", Fingerprint: "fp-a",
		KeyMaterial: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePublicKey(ctx, &store.PublicKey{
		ID: "k-revoked", TenantID: "t1", AccountID: u.ID,
		KeyType: "ssh", Label: "r", Fingerprint: "fp-r",
		KeyMaterial: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICp8mG0v3h9mKq7sUc4dF5gH6jK1lM2nO3pQ4rS5tU7 r@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	// Revoke through the real store path (CreatePublicKey does not persist
	// revoked_at; RevokePublicKey does).
	if err := s.RevokePublicKey(ctx, "t1", u.ID, "k-revoked"); err != nil {
		t.Fatal(err)
	}
	_ = now
	tn := &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}

	rec := do(h.Keys, req(http.MethodGet, "/api/v1/public/keys", tn))
	if rec.Code != http.StatusOK {
		t.Fatalf("keys = %d, want 200", rec.Code)
	}
	keys := decode[[]dto.PublicKey](t, rec)
	if len(keys) != 1 || keys[0].ID != "k-active" {
		t.Fatalf("keys = %+v, want only active", keys)
	}
}
