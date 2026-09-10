package clients_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1clients "github.com/selfagency/sovereign/internal/api/v1/admin/clients"
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

func newHandler(s *store.Store) *v1clients.Handler {
	return v1clients.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:clients:read", "admin:clients:write"}, IsAdmin: true}
}

func nonAdminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "user", TenantID: "tenant-a", Scopes: []string{"self"}, IsAdmin: false}
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

// seedClient inserts a client with a known plaintext secret so tests can
// assert rotation invalidates it. Returns the client id and secret.
func seedClient(t *testing.T, s *store.Store, id, secret string) {
	t.Helper()
	if err := s.CreateClient(context.Background(), &store.Client{ID: id, Secret: secret, RedirectURIs: []string{"https://x/cb"}, Scopes: []string{"openid"}, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
}

func TestListClients(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedClient(t, s, "c1", "secret-one")
	seedClient(t, s, "c2", "secret-two")

	rec := do(h.ListClients, req(http.MethodGet, "/api/v1/admin/clients", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.List[dto.Client]](t, rec)
	if got.Total != 2 || len(got.Data) != 2 {
		t.Fatalf("list = %+v, want 2/2", got)
	}
	// Never leak the argon2id hash or any secret in the response.
	body := rec.Body.String()
	if strings.Contains(body, "$argon2id") {
		t.Fatalf("list response leaks argon2id hash: %s", body)
	}
	if strings.Contains(body, "secret-one") || strings.Contains(body, "secret-two") {
		t.Fatalf("list response leaks plaintext secret: %s", body)
	}
}

func TestGetClientByID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedClient(t, s, "c1", "secret-one")

	rec := do(h.ClientByID, req(http.MethodGet, "/api/v1/admin/clients/c1", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.Client](t, rec)
	if got.ID != "c1" {
		t.Fatalf("client = %+v", got)
	}
	body := rec.Body.String()
	if strings.Contains(body, "$argon2id") || strings.Contains(body, "secret-one") {
		t.Fatalf("get response leaks secret material: %s", body)
	}
}

func TestGetClientByIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.ClientByID, req(http.MethodGet, "/api/v1/admin/clients/missing", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCreateClient(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	body := `{"id":"new-client"}`
	r := req(http.MethodPost, "/api/v1/admin/clients", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	rec := do(h.CreateClient, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	resp := decode[struct {
		Client dto.Client `json:"client"`
		Secret string     `json:"secret"`
	}](t, rec)
	if resp.Client.ID != "new-client" || resp.Secret == "" {
		t.Fatalf("created = %+v, want id + one-time secret", resp)
	}
	// Persisted and readable back (without the secret).
	persisted, err := s.ClientByID(context.Background(), "new-client")
	if err != nil {
		t.Fatalf("ClientByID: %v", err)
	}
	if persisted.Secret == "" || persisted.Secret == resp.Secret {
		t.Fatal("store must hold a hashed secret, not the returned plaintext")
	}
	if !store.VerifyClientSecret(resp.Secret, persisted.Secret) {
		t.Fatal("stored hash must verify against the returned plaintext secret")
	}
}

func TestCreateClientValidation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for _, body := range []string{`{}`, `{"id":""}`, `{`} {
		r := req(http.MethodPost, "/api/v1/admin/clients", adminPrincipal())
		r.Body = io.NopCloser(strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := do(h.CreateClient, r)
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q = %d, want 4xx (body %s)", body, rec.Code, rec.Body.String())
		}
	}
}

func TestCreateClientDuplicateID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedClient(t, s, "c1", "secret-one")
	r := req(http.MethodPost, "/api/v1/admin/clients", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"id":"c1"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.CreateClient, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestDeleteClient(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedClient(t, s, "c1", "secret-one")

	rec := do(h.DeleteClient, req(http.MethodDelete, "/api/v1/admin/clients/c1", adminPrincipal()))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if _, err := s.ClientByID(context.Background(), "c1"); err == nil {
		t.Fatal("client still present after delete")
	}
}

func TestDeleteClientNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.DeleteClient, req(http.MethodDelete, "/api/v1/admin/clients/missing", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestRotateSecretShowOnce(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedClient(t, s, "c1", "old-secret")

	r := req(http.MethodPost, "/api/v1/admin/clients/c1:rotate", adminPrincipal())
	rec := do(h.RotateSecret, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	resp := decode[struct {
		Secret string `json:"secret"`
	}](t, rec)
	newSecret := resp.Secret
	if newSecret == "" || newSecret == "old-secret" {
		t.Fatalf("rotated secret = %q, want a fresh non-empty value", newSecret)
	}

	// The returned plaintext is the one and only exposure: a subsequent
	// get/list must not contain it.
	c, err := s.ClientByID(context.Background(), "c1")
	if err != nil {
		t.Fatalf("ClientByID: %v", err)
	}
	if !store.VerifyClientSecret(newSecret, c.Secret) {
		t.Fatal("stored hash must verify against the returned plaintext")
	}
	if store.VerifyClientSecret("old-secret", c.Secret) {
		t.Fatal("re-rotation must invalidate the old secret")
	}

	getRec := do(h.ClientByID, req(http.MethodGet, "/api/v1/admin/clients/c1", adminPrincipal()))
	if strings.Contains(getRec.Body.String(), newSecret) || strings.Contains(getRec.Body.String(), "$argon2id") {
		t.Fatalf("get after rotate leaks secret: %s", getRec.Body.String())
	}
	listRec := do(h.ListClients, req(http.MethodGet, "/api/v1/admin/clients", adminPrincipal()))
	if strings.Contains(listRec.Body.String(), newSecret) || strings.Contains(listRec.Body.String(), "$argon2id") {
		t.Fatalf("list after rotate leaks secret: %s", listRec.Body.String())
	}
}

func TestRotateSecretNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.RotateSecret, req(http.MethodPost, "/api/v1/admin/clients/missing:rotate", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestRotateSecretEmptyID verifies that a path segment that reduces to an
// empty id after stripping the :rotate suffix yields 404, not a store call.
func TestRotateSecretEmptyID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.RotateSecret, req(http.MethodPost, "/api/v1/admin/clients/:rotate", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty id = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestNonAdminPrincipalForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedClient(t, s, "c1", "secret-one")

	cases := []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"list", func() *httptest.ResponseRecorder {
			return do(h.ListClients, req(http.MethodGet, "/api/v1/admin/clients", nonAdminPrincipal()))
		}},
		{"get", func() *httptest.ResponseRecorder {
			return do(h.ClientByID, req(http.MethodGet, "/api/v1/admin/clients/c1", nonAdminPrincipal()))
		}},
		{"create", func() *httptest.ResponseRecorder {
			return do(h.CreateClient, req(http.MethodPost, "/api/v1/admin/clients", nonAdminPrincipal()))
		}},
		{"delete", func() *httptest.ResponseRecorder {
			return do(h.DeleteClient, req(http.MethodDelete, "/api/v1/admin/clients/c1", nonAdminPrincipal()))
		}},
		{"rotate", func() *httptest.ResponseRecorder {
			return do(h.RotateSecret, req(http.MethodPost, "/api/v1/admin/clients/c1:rotate", nonAdminPrincipal()))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.do()
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s = %d, want 403 (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.ListClients, req(http.MethodGet, "/api/v1/admin/clients", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestNewNilLogger(t *testing.T) {
	s := testStore(t)
	h := v1clients.New(s, nil) // must not panic and must accept a nil logger
	if h == nil {
		t.Fatal("New with nil logger returned nil handler")
	}
}

// TestClosedStoreInternal verifies every handler degrades to an internal-error
// (500) response, never a panic, when the underlying store fails.
func TestClosedStoreInternal(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	h := newHandler(s)

	cases := []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"list", func() *httptest.ResponseRecorder {
			return do(h.ListClients, req(http.MethodGet, "/api/v1/admin/clients", adminPrincipal()))
		}},
		{"get", func() *httptest.ResponseRecorder {
			return do(h.ClientByID, req(http.MethodGet, "/api/v1/admin/clients/c1", adminPrincipal()))
		}},
		{"create", func() *httptest.ResponseRecorder {
			r := req(http.MethodPost, "/api/v1/admin/clients", adminPrincipal())
			r.Body = io.NopCloser(strings.NewReader(`{"id":"c1"}`))
			return do(h.CreateClient, r)
		}},
		{"delete", func() *httptest.ResponseRecorder {
			return do(h.DeleteClient, req(http.MethodDelete, "/api/v1/admin/clients/c1", adminPrincipal()))
		}},
		{"rotate", func() *httptest.ResponseRecorder {
			return do(h.RotateSecret, req(http.MethodPost, "/api/v1/admin/clients/c1:rotate", adminPrincipal()))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.do()
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s = %d, want 500 (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}
