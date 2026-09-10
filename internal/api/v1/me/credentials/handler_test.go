package credentials_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1creds "github.com/selfagency/sovereign/internal/api/v1/me/credentials"
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

func newHandler(s *store.Store) *v1creds.Handler {
	return v1creds.New(s, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
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

func seedCred(t *testing.T, s *store.Store, id, userID string, credID []byte) {
	t.Helper()
	ctx := context.Background()
	// webauthn_credentials has an FK to users; ensure the user + tenant exist.
	if err := s.CreateTenant(ctx, &store.Tenant{ID: "tenant-1", Handle: "tenant-1.example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	if _, err := s.UserByID(ctx, userID); err != nil {
		if err := s.CreateUser(ctx, &store.User{ID: userID, TenantID: "tenant-1", Handle: userID}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddWebAuthnCredential(ctx, &store.WebAuthnCredential{
		ID: id, UserID: userID, CredentialID: credID, PublicKey: []byte("pk"),
		Data: []byte("{}"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestListReturnsMetadataOnly(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedCred(t, s, "c1", "u1", []byte("cred1"))
	seedCred(t, s, "c2", "u1", []byte("cred2"))

	rec := do(h.List, req(http.MethodGet, "/api/v1/me/credentials", &middleware.Principal{UserID: "u1", Scopes: []string{"credentials:read"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var out []dto.WebAuthnCredential
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d credentials, want 2", len(out))
	}
	if out[0].CredentialID != base64.RawURLEncoding.EncodeToString([]byte("cred1")) {
		t.Fatalf("credential_id = %q", out[0].CredentialID)
	}
	// The go-webauthn Data / public key must never be exposed.
	body := rec.Body.String()
	if bytes.Contains([]byte(body), []byte("{}")) && bytes.Contains([]byte(body), []byte("data")) {
		t.Fatalf("list leaked credential data: %s", body)
	}
}

func TestDeleteOwnCredential(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedCred(t, s, "c1", "u1", []byte("cred1"))
	seedCred(t, s, "c2", "u1", []byte("cred2"))

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/credentials/c1", &middleware.Principal{UserID: "u1", Scopes: []string{"credentials:write"}}))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if _, err := s.GetWebAuthnCredential(context.Background(), []byte("cred1")); err == nil {
		t.Fatal("credential c1 should be deleted")
	}
}

func TestDeleteLastCredentialConflict(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedCred(t, s, "c1", "u1", []byte("cred1"))

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/credentials/c1", &middleware.Principal{UserID: "u1", Scopes: []string{"credentials:write"}}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (last credential)", rec.Code)
	}
	// The credential is preserved.
	if _, err := s.GetWebAuthnCredential(context.Background(), []byte("cred1")); err != nil {
		t.Fatal("last credential should be preserved on 409")
	}
}

func TestDeleteForeignCredentialNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedCred(t, s, "c-other", "other", []byte("cred-other"))

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/credentials/c-other", &middleware.Principal{UserID: "u1", Scopes: []string{"credentials:write"}}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user delete status = %d, want 404", rec.Code)
	}
	if _, err := s.GetWebAuthnCredential(context.Background(), []byte("cred-other")); err != nil {
		t.Fatal("foreign credential should remain")
	}
}

func TestDeleteUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/credentials/c1", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
