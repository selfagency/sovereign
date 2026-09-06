package tokens_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1tokens "github.com/selfagency/sovereign/internal/api/v1/me/tokens"
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

func newHandler(s *store.Store) *v1tokens.Handler {
	return v1tokens.New(s, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
}

func principal(userID string, scopes []string) *middleware.Principal {
	return &middleware.Principal{UserID: userID, TenantID: "tenant-1", Scopes: scopes}
}

func req(method, path string, p *middleware.Principal, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, http.NoBody)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
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

// TestCreateReturnsTokenOnce verifies a successful create returns the raw
// token in the response and persists only its hash.
func TestCreateReturnsTokenOnce(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	ctx := context.Background()

	rec := do(h.Create, req(http.MethodPost, "/api/v1/me/tokens", principal("u1", []string{"keys:read", "profile:read"}), `{"scopes":["keys:read"],"name":"ci"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out dto.APITokenCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" {
		t.Fatal("create response missing raw token")
	}
	// Only the hash is stored; the raw token is not re-readable.
	got, err := s.GetAPIToken(ctx, store.HashAPIToken(out.Token))
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenHash == out.Token || strings.Contains(got.TokenHash, out.Token) {
		t.Fatalf("stored token_hash leaks plaintext: %q", got.TokenHash)
	}
}

// TestCreateScopeSubsetSelection verifies a requested scope not granted to the
// principal is rejected, while a granted subset succeeds.
func TestCreateScopeSubsetSelection(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)

	// Requesting a scope the principal does not hold -> 422.
	rec := do(h.Create, req(http.MethodPost, "/api/v1/me/tokens", principal("u1", []string{"keys:read"}), `{"scopes":["admin:tenants"]}`))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("not-granted scope status = %d, want 422", rec.Code)
	}

	// Empty scope set -> 422.
	rec = do(h.Create, req(http.MethodPost, "/api/v1/me/tokens", principal("u1", []string{"keys:read"}), `{"scopes":[]}`))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty scope status = %d, want 422", rec.Code)
	}

	// Granted subset -> 201.
	rec = do(h.Create, req(http.MethodPost, "/api/v1/me/tokens", principal("u1", []string{"keys:read"}), `{"scopes":["keys:read"]}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("granted scope status = %d, want 201", rec.Code)
	}
}

// TestCreateUnauthenticated verifies a missing principal is a 401.
func TestCreateUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Create, req(http.MethodPost, "/api/v1/me/tokens", nil, `{"scopes":["keys:read"]}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestListNeverReturnsToken verifies list returns metadata only, never the
// raw token or its hash.
func TestListNeverReturnsToken(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	ctx := context.Background()
	if err := s.CreateAPIToken(ctx, &store.APIToken{
		ID: "t1", UserID: "u1", TokenHash: store.HashAPIToken("secret"), FamilyID: "f",
		Scopes: []string{"keys:read"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	rec := do(h.List, req(http.MethodGet, "/api/v1/me/tokens", principal("u1", []string{"keys:read"}), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret") || strings.Contains(body, "token_hash") {
		t.Fatalf("list leaked token material: %s", body)
	}
}

// TestRevokeScopedToUser verifies revoking a token family belonging to another
// user is a 404 and leaves the foreign token intact.
func TestRevokeScopedToUser(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	ctx := context.Background()
	if err := s.CreateAPIToken(ctx, &store.APIToken{
		ID: "t-other", UserID: "other", TokenHash: store.HashAPIToken("x"), FamilyID: "fam-other",
		Scopes: []string{"keys:read"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	rec := do(h.Revoke, req(http.MethodDelete, "/api/v1/me/tokens/fam-other", principal("u1", []string{"keys:read"}), ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user revoke status = %d, want 404", rec.Code)
	}
	if _, err := s.GetAPIToken(ctx, store.HashAPIToken("x")); err != nil {
		t.Fatalf("foreign token should remain: %v", err)
	}

	// Own token family revokes cleanly.
	if err := s.CreateAPIToken(ctx, &store.APIToken{
		ID: "t-mine", UserID: "u1", TokenHash: store.HashAPIToken("y"), FamilyID: "fam-mine",
		Scopes: []string{"keys:read"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	rec = do(h.Revoke, req(http.MethodDelete, "/api/v1/me/tokens/fam-mine", principal("u1", []string{"keys:read"}), ""))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("own revoke status = %d, want 204", rec.Code)
	}
	if _, err := s.GetAPIToken(ctx, store.HashAPIToken("y")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked token should be gone, got %v", err)
	}
}
