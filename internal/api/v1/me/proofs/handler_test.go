package proofs_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1proofs "github.com/selfagency/sovereign/internal/api/v1/me/proofs"
	"github.com/selfagency/sovereign/internal/proofs"
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

func seedClaim(t *testing.T, s *store.Store, u *store.User, id string) *store.ProofClaim {
	return seedClaimAt(t, s, u, id, "dns", "_atproto.example.com")
}

// seedClaimAt seeds a claim with an explicit service + claim_location so tests
// can create multiple claims without tripping the UNIQUE(tenant_id, service,
// claim_location) constraint.
func seedClaimAt(t *testing.T, s *store.Store, u *store.User, id, service, loc string) *store.ProofClaim {
	t.Helper()
	c := &store.ProofClaim{
		ID: id, TenantID: u.TenantID, AccountID: u.ID,
		AnchorType: "did", AnchorValue: "did:plc:x", Service: service,
		ClaimLocation: loc, ExpectedToken: "did:plc:x", Status: "pending",
	}
	if err := s.CreateProofClaim(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

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

func principal(userID, tenantID string) *middleware.Principal {
	return &middleware.Principal{UserID: userID, TenantID: tenantID, Scopes: []string{"self"}}
}

// fakeResolver resolves hosts to fixed IPs, mirroring the internal/proofs test
// stub so the SSRF guard can be exercised without real DNS.
type fakeResolver struct {
	ips map[string][]net.IPAddr
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, errors.New("no txt")
}

func newHandler(s *store.Store, v *proofs.Verifier) *v1proofs.Handler {
	return v1proofs.New(s, v, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestListProofs(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedClaim(t, s, u, "p1")
	seedClaimAt(t, s, u, "p2", "github_gist", "https://gist.github.com/alice")

	rec := do(h.List, req(http.MethodGet, "/api/v1/me/proofs", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[[]dto.ProofClaim](t, rec)
	if len(got) != 2 {
		t.Fatalf("list = %d claims, want 2", len(got))
	}
	if got[0].UserID != u.ID || got[0].Status != "pending" {
		t.Fatalf("claim = %+v", got[0])
	}
}

func TestListProofsEmpty(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.List, req(http.MethodGet, "/api/v1/me/proofs", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rec.Code)
	}
	got := decode[[]dto.ProofClaim](t, rec)
	if len(got) != 0 {
		t.Fatalf("list = %d claims, want 0", len(got))
	}
}

func TestListProofsUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	rec := do(h.List, req(http.MethodGet, "/api/v1/me/proofs", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestGetProof(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedClaim(t, s, u, "p1")

	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/proofs/p1", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.ProofClaim](t, rec)
	if got.ID != "p1" || got.UserID != u.ID {
		t.Fatalf("get = %+v", got)
	}
}

func TestGetProofNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/proofs/missing", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCreateProof(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	body := `{"anchor_type":"did","anchor_value":"did:plc:x","service":"dns","claim_location":"_atproto.example.com","expected_token":"did:plc:x"}`
	r := req(http.MethodPost, "/api/v1/me/proofs", principal(u.ID, u.TenantID))
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	rec := do(h.Create, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.ProofClaim](t, rec)
	if got.ID == "" || got.Status != "pending" || got.UserID != u.ID {
		t.Fatalf("created = %+v", got)
	}
	// Persisted.
	persisted, err := s.GetProofClaim(context.Background(), u.TenantID, got.ID)
	if err != nil || persisted.Status != "pending" {
		t.Fatalf("persisted: err=%v claim=%+v", err, persisted)
	}
}

func TestCreateProofValidation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")

	cases := []struct {
		name string
		body string
	}{
		{"empty-body", `{}`},
		{"missing-anchor-type", `{"anchor_value":"x","service":"dns","claim_location":"_a.example","expected_token":"t"}`},
		{"bad-service", `{"anchor_type":"did","anchor_value":"x","service":"xmpp","claim_location":"_a.example","expected_token":"t"}`},
		{"non-url-location", `{"anchor_type":"did","anchor_value":"x","service":"custom_url","claim_location":"not-a-url","expected_token":"t"}`},
		{"missing-token", `{"anchor_type":"did","anchor_value":"x","service":"dns","claim_location":"_a.example"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := req(http.MethodPost, "/api/v1/me/proofs", principal(u.ID, u.TenantID))
			r.Body = io.NopCloser(strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			rec := do(h.Create, r)
			if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 4xx (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCreateProofDuplicate(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedClaim(t, s, u, "p1")
	// Same service + claim_location as the seeded claim -> duplicate.
	body := `{"anchor_type":"did","anchor_value":"did:plc:x","service":"dns","claim_location":"_atproto.example.com","expected_token":"did:plc:x"}`
	r := req(http.MethodPost, "/api/v1/me/proofs", principal(u.ID, u.TenantID))
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Create, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestDeleteProof(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedClaim(t, s, u, "p1")

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/proofs/p1", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if _, err := s.GetProofClaim(context.Background(), u.TenantID, "p1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim not deleted: %v", err)
	}
}

func TestDeleteProofNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/proofs/missing", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestVerifyProofDNS verifies a DNS claim end to end: the verifier resolves
// the TXT record, the status is persisted as verified, and the response
// reflects it.
func TestVerifyProofDNS(t *testing.T) {
	s := testStore(t)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedClaim(t, s, u, "p1")
	v := &proofs.Verifier{Resolver: &stubTXTResolver{txts: map[string][]string{
		"_atproto.example.com": {"did=did:plc:x"},
	}}}
	h := newHandler(s, v)

	rec := do(h.Verify, req(http.MethodPost, "/api/v1/me/proofs/p1/verify", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.ProofClaim](t, rec)
	if got.Status != "verified" {
		t.Fatalf("verify status = %q, want verified", got.Status)
	}
	persisted, err := s.GetProofClaim(context.Background(), u.TenantID, "p1")
	if err != nil || persisted.Status != "verified" {
		t.Fatalf("persisted: err=%v claim=%+v", err, persisted)
	}
}

// TestVerifyProofNotFound verifies a missing claim returns 404.
func TestVerifyProofNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Verify, req(http.MethodPost, "/api/v1/me/proofs/missing/verify", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("verify missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestVerifyProofSSRFNegative verifies that a claim pointing at a
// loopback/private/link-local/metadata address is REJECTED by the SSRF guard
// and never attempted. The status is persisted as failed and the response
// carries the failure.
func TestVerifyProofSSRFNegative(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/",       // loopback
		"http://10.0.0.1/",        // private
		"http://169.254.169.254/", // cloud metadata (link-local)
		"http://192.168.1.1/",     // private
		"http://[fe80::1]/",       // link-local unicast
	}
	for _, loc := range blocked {
		t.Run(loc, func(t *testing.T) {
			s := testStore(t)
			u := seedTenantUser(t, s, "tenant-a", "alice")
			host := hostFromURL(loc)
			// The resolver returns the blocked IP for the host, so the SSRF
			// guard fires before any HTTP request is made.
			v := &proofs.Verifier{
				HTTPClient: &http.Client{},
				Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
					host: {{IP: net.ParseIP(hostIP(loc))}},
				}},
			}
			h := newHandler(s, v)
			seedClaim(t, s, u, "p1")
			// Point the claim at the blocked location.
			if err := s.UpdateProofClaimStatus(context.Background(), u.TenantID, "p1", "pending", ""); err != nil {
				t.Fatal(err)
			}
			// Rewrite the claim's location to the blocked URL.
			updateClaimLocation(t, s, u.TenantID, "p1", loc)

			rec := do(h.Verify, req(http.MethodPost, "/api/v1/me/proofs/p1/verify", principal(u.ID, u.TenantID)))
			if rec.Code != http.StatusOK {
				t.Fatalf("verify = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			got := decode[dto.ProofClaim](t, rec)
			if got.Status != "failed" {
				t.Fatalf("status = %q, want failed (SSRF guard did not fire)", got.Status)
			}
			persisted, err := s.GetProofClaim(context.Background(), u.TenantID, "p1")
			if err != nil || persisted.Status != "failed" {
				t.Fatalf("persisted: err=%v claim=%+v", err, persisted)
			}
			if persisted.LastError == "" {
				t.Fatal("expected a non-empty last_error from the SSRF guard")
			}
		})
	}
}

// TestVerifyProofSSRFPublicAllowed verifies a claim resolving to a public IP
// is attempted (the guard passes) and the fetch proceeds.
func TestVerifyProofSSRFPublicAllowed(t *testing.T) {
	s := testStore(t)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedClaim(t, s, u, "p1")
	updateClaimLocation(t, s, u.TenantID, "p1", "https://example.com/proof")
	v := &proofs.Verifier{
		HTTPClient: &http.Client{},
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("93.184.216.34")}},
		}},
	}
	h := newHandler(s, v)
	rec := do(h.Verify, req(http.MethodPost, "/api/v1/me/proofs/p1/verify", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.ProofClaim](t, rec)
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed (token absent)", got.Status)
	}
}

// TestCrossTenantIsolation verifies a tenant A principal cannot read or write
// tenant B's proofs: every operation is scoped to the principal's tenant, so
// B's claims are unreachable (404).
func TestCrossTenantIsolation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, nil)
	a := seedTenantUser(t, s, "tenant-a", "alice")
	b := seedTenantUser(t, s, "tenant-b", "bob")
	seedClaim(t, s, b, "b1")

	// A cannot get B's claim.
	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/proofs/b1", principal(a.ID, a.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("A get B claim = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	// A cannot delete B's claim.
	rec = do(h.Delete, req(http.MethodDelete, "/api/v1/me/proofs/b1", principal(a.ID, a.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("A delete B claim = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	// A cannot verify B's claim.
	rec = do(h.Verify, req(http.MethodPost, "/api/v1/me/proofs/b1/verify", principal(a.ID, a.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("A verify B claim = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	// B's claim is untouched.
	persisted, err := s.GetProofClaim(context.Background(), b.TenantID, "b1")
	if err != nil || persisted.Status != "pending" {
		t.Fatalf("B claim mutated: err=%v claim=%+v", err, persisted)
	}
	// A's list does not include B's claim.
	rec = do(h.List, req(http.MethodGet, "/api/v1/me/proofs", principal(a.ID, a.TenantID)))
	got := decode[[]dto.ProofClaim](t, rec)
	if len(got) != 0 {
		t.Fatalf("A list = %d claims, want 0 (leak)", len(got))
	}
}

// --- test helpers ---

// stubTXTResolver resolves TXT records.
type stubTXTResolver struct {
	txts map[string][]string
}

func (s *stubTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txts, ok := s.txts[name]; ok {
		return txts, nil
	}
	return nil, errors.New("no such host")
}

func (s *stubTXTResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return nil, errors.New("no ip")
}

// updateClaimLocation rewrites a claim's claim_location directly in the DB so
// tests can point a claim at an arbitrary URL without going through the
// handler's create validation.
func updateClaimLocation(t *testing.T, s *store.Store, tenantID, id, loc string) {
	t.Helper()
	_, err := s.DB().ExecContext(context.Background(),
		`UPDATE proof_claims SET claim_location = ?, service = 'custom_url' WHERE tenant_id = ? AND id = ?`,
		loc, tenantID, id)
	if err != nil {
		t.Fatal(err)
	}
}

// hostFromURL extracts the host from a URL string (mirrors internal/proofs).
func hostFromURL(raw string) string {
	rest := raw
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	if idx := strings.IndexAny(rest, "/?"); idx >= 0 {
		rest = rest[:idx]
	}
	if idx := strings.Index(rest, ":"); idx >= 0 {
		rest = rest[:idx]
	}
	return rest
}

// hostIP returns the IP literal embedded in a blocked URL (strips brackets
// from IPv6 literals).
func hostIP(raw string) string {
	host := hostFromURL(raw)
	return strings.Trim(host, "[]")
}
