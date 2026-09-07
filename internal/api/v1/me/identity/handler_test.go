package identity_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1identity "github.com/selfagency/sovereign/internal/api/v1/me/identity"
	"github.com/selfagency/sovereign/internal/store"
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

func seedTenantUser(t *testing.T, s *store.Store, tenantID, handle string) *store.User {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &store.Tenant{ID: tenantID, Handle: handle + ".example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	u := &store.User{ID: "user-" + tenantID + "-" + handle, TenantID: tenantID, Handle: handle, DisplayName: handle}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

// req builds an httptest request carrying the given principal in context.
func req(method, path string, p *middleware.Principal) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	if p != nil {
		r = r.WithContext(middleware.WithPrincipal(r.Context(), p))
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

func newHandler(s *store.Store) *v1identity.Handler {
	return v1identity.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func principal(userID, tenantID string) *middleware.Principal {
	return &middleware.Principal{UserID: userID, TenantID: tenantID, Scopes: []string{"self"}}
}

func TestGetIdentity(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")

	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/identity", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("get identity = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.User](t, rec)
	if got.ID != u.ID || got.TenantID != "tenant-a" || got.DisplayName != "alice" {
		t.Fatalf("identity = %+v", got)
	}
	if got.TOSAccepted {
		t.Error("fresh user tos_accepted should be false")
	}
}

func TestGetIdentityUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/identity", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestGetIdentityNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	// Principal references a user that does not exist.
	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/identity", principal("missing-user", "tenant-a")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing user = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestUpdateIdentity(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	body := `{"email":"alice@example.com","display_name":"Alice A."}`
	r := req(http.MethodPatch, "/api/v1/me/identity", principal(u.ID, u.TenantID))
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	rec := do(h.Update, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.User](t, rec)
	if got.Email != "alice@example.com" || got.DisplayName != "Alice A." {
		t.Fatalf("updated identity = %+v", got)
	}
	// Persisted.
	persisted, err := s.UserByID(context.Background(), u.ID)
	if err != nil || persisted.Email != "alice@example.com" || persisted.DisplayName != "Alice A." {
		t.Fatalf("persisted: err=%v user=%+v", err, persisted)
	}
}

func TestUpdateIdentityValidation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")

	cases := []struct {
		name string
		body string
	}{
		{"empty-body", `{}`},
		{"bad-email", `{"email":"not-an-email"}`},
		{"empty-display-name", `{"display_name":"  "}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := req(http.MethodPatch, "/api/v1/me/identity", principal(u.ID, u.TenantID))
			r.Body = io.NopCloser(strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			rec := do(h.Update, r)
			if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 4xx (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUpdateIdentityPATCHSemantics(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	// Seed an email, then PATCH only display_name: email must be preserved.
	if err := s.SetUserEmail(context.Background(), u.ID, "seed@example.com"); err != nil {
		t.Fatal(err)
	}
	r := req(http.MethodPatch, "/api/v1/me/identity", principal(u.ID, u.TenantID))
	r.Body = io.NopCloser(strings.NewReader(`{"display_name":"New Name"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Update, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.User](t, rec)
	if got.DisplayName != "New Name" || got.Email != "seed@example.com" {
		t.Fatalf("patch semantics violated: %+v", got)
	}
}

func TestOnboardingState(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)

	t.Run("fresh", func(t *testing.T) {
		u := seedTenantUser(t, s, "tenant-fresh", "new")
		rec := do(h.OnboardingState, req(http.MethodGet, "/api/v1/me/identity/onboarding", principal(u.ID, u.TenantID)))
		if rec.Code != http.StatusOK {
			t.Fatalf("onboarding = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		onb := decode[v1identity.Onboarding](t, rec)
		if onb.ToSAccepted || onb.HasPasskey || onb.HasProfile || onb.Complete {
			t.Fatalf("fresh onboarding = %+v, want all false", onb)
		}
	})

	t.Run("complete", func(t *testing.T) {
		u := seedTenantUser(t, s, "tenant-full", "done")
		ctx := context.Background()
		if err := s.SetToSAccepted(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := s.SetPasskeySetup(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertProfilePage(ctx, &store.ProfilePage{
			ID: "page-1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "done", IsPublished: true,
		}); err != nil {
			t.Fatal(err)
		}
		rec := do(h.OnboardingState, req(http.MethodGet, "/api/v1/me/identity/onboarding", principal(u.ID, u.TenantID)))
		if rec.Code != http.StatusOK {
			t.Fatalf("onboarding = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		onb := decode[v1identity.Onboarding](t, rec)
		if !onb.ToSAccepted || !onb.HasPasskey || !onb.HasProfile || !onb.Complete {
			t.Fatalf("complete onboarding = %+v, want all true", onb)
		}
	})
}

func TestAcceptToS(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")

	rec := do(h.AcceptToS, req(http.MethodPost, "/api/v1/me/identity/tos", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("accept tos = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	persisted, err := s.UserByID(context.Background(), u.ID)
	if err != nil || !persisted.ToSAccepted {
		t.Fatalf("tos not persisted: err=%v user=%+v", err, persisted)
	}
	// Idempotent: accepting again stays 200.
	rec2 := do(h.AcceptToS, req(http.MethodPost, "/api/v1/me/identity/tos", principal(u.ID, u.TenantID)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("accept tos again = %d, want 200", rec2.Code)
	}
}

func TestRequestDeletionCreatesPendingWithoutCascade(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	if err := s.SetUserEmail(ctx, u.ID, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	rec := do(h.RequestDeletion, req(http.MethodPost, "/api/v1/me/identity/deletion", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("request deletion = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.PendingDeletion](t, rec)
	if got.Status != "pending" || got.UserID != u.ID {
		t.Fatalf("pending deletion = %+v", got)
	}
	// The user row must still exist (no cascade) and retain its data.
	persisted, err := s.UserByID(ctx, u.ID)
	if err != nil || persisted.Email != "alice@example.com" {
		t.Fatalf("user cascade-deleted: err=%v user=%+v", err, persisted)
	}
	// The request is readable back.
	if _, err := s.PendingDeletionByUser(ctx, u.ID); err != nil {
		t.Fatalf("pending deletion not persisted: %v", err)
	}
}

func TestRequestDeletionNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.RequestDeletion, req(http.MethodPost, "/api/v1/me/identity/deletion", principal("missing-user", "tenant-a")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deletion for missing user = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestExport(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	if err := s.SetUserEmail(ctx, u.ID, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	// Seed profile page + link + key + proof for a populated export.
	if err := s.UpsertProfilePage(ctx, &store.ProfilePage{
		ID: "page-1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "alice", Bio: "hi", IsPublished: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProfileLink(ctx, &store.ProfileLink{
		ID: "link-1", ProfilePageID: "page-1", Position: 0, Kind: "url", Label: "home", URL: "https://alice.example",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePublicKey(ctx, &store.PublicKey{
		ID: "key-1", TenantID: u.TenantID, AccountID: u.ID, KeyType: "ssh", Label: "laptop", Fingerprint: "fp1", KeyMaterial: "ssh-ed25519 AAAA...",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProofClaim(ctx, &store.ProofClaim{
		ID: "proof-1", TenantID: u.TenantID, AccountID: u.ID, AnchorType: "dns", AnchorValue: "alice.example",
		Service: "github", ClaimLocation: "alice", ExpectedToken: "tok", Status: "verified",
	}); err != nil {
		t.Fatal(err)
	}

	rec := do(h.Export, req(http.MethodGet, "/api/v1/me/identity/export", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	exp := decode[v1identity.Export](t, rec)
	if exp.User.ID != u.ID || exp.User.Email != "alice@example.com" {
		t.Fatalf("export user = %+v", exp.User)
	}
	if exp.Profile == nil || exp.Profile.Bio != "hi" {
		t.Fatalf("export profile = %+v", exp.Profile)
	}
	if len(exp.Links) != 1 || exp.Links[0].URL != "https://alice.example" {
		t.Fatalf("export links = %+v", exp.Links)
	}
	if len(exp.Keys) != 1 || exp.Keys[0].Fingerprint != "fp1" {
		t.Fatalf("export keys = %+v", exp.Keys)
	}
	if len(exp.Proofs) != 1 || exp.Proofs[0].Status != "verified" {
		t.Fatalf("export proofs = %+v", exp.Proofs)
	}
}

func TestExportFreshUserEmptyCollections(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "empty")
	rec := do(h.Export, req(http.MethodGet, "/api/v1/me/identity/export", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	exp := decode[v1identity.Export](t, rec)
	if exp.Profile != nil {
		t.Fatalf("fresh user profile should be omitted, got %+v", exp.Profile)
	}
	if len(exp.Links) != 0 || len(exp.Keys) != 0 || len(exp.Proofs) != 0 {
		t.Fatalf("fresh export collections should be empty: %+v", exp)
	}
}

func TestCrossTenantIsolation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	a := seedTenantUser(t, s, "tenant-a", "alice")
	b := seedTenantUser(t, s, "tenant-b", "bob")
	if err := s.SetUserEmail(context.Background(), b.ID, "bob@example.com"); err != nil {
		t.Fatal(err)
	}

	// Principal from tenant A must not observe tenant B's identity: the subject
	// is always the principal's own user ID, so B's email is unreachable.
	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/identity", principal(a.ID, a.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("get A = %d (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.User](t, rec)
	if got.ID != a.ID || got.Email != "" {
		t.Fatalf("principal A saw wrong identity: %+v", got)
	}
	// A principal cannot act on B's deletion request either: CreatePendingDeletion
	// is keyed to the principal's own user, and requesting for A never touches B.
	delA := do(h.RequestDeletion, req(http.MethodPost, "/api/v1/me/identity/deletion", principal(a.ID, a.TenantID)))
	if delA.Code != http.StatusCreated {
		t.Fatalf("request deletion A = %d", delA.Code)
	}
	if _, err := s.PendingDeletionByUser(context.Background(), b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant A's deletion request leaked to tenant B: %v", err)
	}
}

// TestNewNilLogger verifies New defaults the logger when nil is passed.
func TestNewNilLogger(t *testing.T) {
	s := testStore(t)
	h := v1identity.New(s, nil)
	if h == nil {
		t.Fatal("New with nil logger returned nil handler")
	}
}

// TestSelfInternalError verifies a store failure loading the user (other than
// not-found) surfaces as a 500.
func TestSelfInternalError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = middleware.WithPrincipal(ctx, principal("u1", "tenant-a"))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me/identity", http.NoBody).WithContext(ctx)
	rec := do(h.Get, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("self internal = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestOnboardingStateInternalError verifies a non-NotFound profile lookup
// failure surfaces as a 500.
func TestOnboardingStateInternalError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = middleware.WithPrincipal(ctx, principal(u.ID, u.TenantID))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me/identity/onboarding", http.NoBody).WithContext(ctx)
	rec := do(h.OnboardingState, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("onboarding internal = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestAcceptToSInternalError verifies a store failure accepting ToS surfaces
// as a 500.
func TestAcceptToSInternalError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = middleware.WithPrincipal(ctx, principal(u.ID, u.TenantID))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/identity/tos", http.NoBody).WithContext(ctx)
	rec := do(h.AcceptToS, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("accept tos internal = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestRequestDeletionInternalError verifies a store failure creating the
// pending deletion surfaces as a 500.
func TestRequestDeletionInternalError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = middleware.WithPrincipal(ctx, principal(u.ID, u.TenantID))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/identity/deletion", http.NoBody).WithContext(ctx)
	rec := do(h.RequestDeletion, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("request deletion internal = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestUpdateIdentityInternalError verifies a store failure persisting an email
// update surfaces as a 500.
func TestUpdateIdentityInternalError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = middleware.WithPrincipal(ctx, principal(u.ID, u.TenantID))
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/me/identity", strings.NewReader(`{"email":"a@b.c"}`)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Update, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("update internal = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestUpdateIdentityInvalidBody verifies a malformed update body is a 400.
func TestUpdateIdentityInvalidBody(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	r := req(http.MethodPatch, "/api/v1/me/identity", principal(u.ID, u.TenantID))
	r.Body = io.NopCloser(strings.NewReader(`{`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Update, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("update bad body = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestExportInternalError verifies a store failure listing keys surfaces as a
// 500 (the export handler logs and continues on profile/link errors but the
// user load failure is fatal).
func TestExportInternalError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = middleware.WithPrincipal(ctx, principal(u.ID, u.TenantID))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me/identity/export", http.NoBody).WithContext(ctx)
	rec := do(h.Export, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("export internal = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}
