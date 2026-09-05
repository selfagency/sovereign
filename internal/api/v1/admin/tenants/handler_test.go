package tenants_test

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
	v1tenants "github.com/selfagency/sovereign/internal/api/v1/admin/tenants"
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

func newHandler(s *store.Store) *v1tenants.Handler {
	return v1tenants.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:tenants:read", "admin:tenants:write"}, IsAdmin: true}
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

func seedTenant(t *testing.T, s *store.Store, id, handle, did string) {
	t.Helper()
	if err := s.CreateTenant(context.Background(), &store.Tenant{ID: id, Handle: handle, DIDMethod: "web", DID: did, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
}

func TestListTenants(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "a.example.com", "did:web:a.example.com")
	seedTenant(t, s, "t2", "b.example.com", "did:web:b.example.com")

	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/tenants?limit=10&offset=0", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.List[dto.Tenant]](t, rec)
	if got.Total != 2 || len(got.Data) != 2 {
		t.Fatalf("list = %+v, want 2/2", got)
	}
	// Ordered by handle.
	if got.Data[0].Handle != "a.example.com" || got.Data[1].Handle != "b.example.com" {
		t.Fatalf("order = %+v", got.Data)
	}
}

func TestListTenantsPagination(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for i := 0; i < 3; i++ {
		seedTenant(t, s, "t"+string(rune('0'+i)), "t"+string(rune('0'+i))+".example.com", "did:web:t"+string(rune('0'+i)))
	}
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/tenants?limit=2&offset=0", adminPrincipal()))
	got := decode[dto.List[dto.Tenant]](t, rec)
	if got.Total != 3 || len(got.Data) != 2 {
		t.Fatalf("page1 = %+v, want total 3 len 2", got)
	}
	rec2 := do(h.List, req(http.MethodGet, "/api/v1/admin/tenants?limit=2&offset=2", adminPrincipal()))
	got2 := decode[dto.List[dto.Tenant]](t, rec2)
	if len(got2.Data) != 1 {
		t.Fatalf("page2 = %+v, want len 1", got2)
	}
}

func TestListTenantsInvalidPagination(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for _, q := range []string{"limit=abc", "limit=-1", "offset=xyz"} {
		rec := do(h.List, req(http.MethodGet, "/api/v1/admin/tenants?"+q, adminPrincipal()))
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 4xx", q, rec.Code)
		}
	}
}

func TestGetTenantByID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "a.example.com", "did:web:a.example.com")

	rec := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/tenants/t1", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("get by id = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.Tenant](t, rec)
	if got.ID != "t1" || got.Handle != "a.example.com" || got.DID != "did:web:a.example.com" {
		t.Fatalf("tenant = %+v", got)
	}
}

func TestGetTenantByIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/tenants/missing", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestGetTenantByDID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "a.example.com", "did:web:a.example.com")

	rec := do(h.GetByDID, req(http.MethodGet, "/api/v1/admin/tenants/by-did/did:web:a.example.com", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("get by did = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.Tenant](t, rec)
	if got.ID != "t1" || got.DID != "did:web:a.example.com" {
		t.Fatalf("tenant = %+v", got)
	}
}

func TestGetTenantByDIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.GetByDID, req(http.MethodGet, "/api/v1/admin/tenants/by-did/did:web:nope", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCreateTenant(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	body := `{"handle":"new.example.com","did":"did:web:new.example.com"}`
	r := req(http.MethodPost, "/api/v1/admin/tenants", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	rec := do(h.Create, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.Tenant](t, rec)
	if got.Handle != "new.example.com" || got.DID != "did:web:new.example.com" || got.ID == "" {
		t.Fatalf("created tenant = %+v", got)
	}
	// Persisted and readable back.
	persisted, err := s.GetTenantByID(context.Background(), got.ID)
	if err != nil || persisted.Handle != "new.example.com" {
		t.Fatalf("persisted: err=%v tenant=%+v", err, persisted)
	}
}

func TestCreateTenantWithExplicitID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	body := `{"id":"custom-id","handle":"c.example.com","did":"did:web:c.example.com"}`
	r := req(http.MethodPost, "/api/v1/admin/tenants", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	rec := do(h.Create, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.Tenant](t, rec)
	if got.ID != "custom-id" {
		t.Fatalf("id = %q, want custom-id", got.ID)
	}
}

func TestCreateTenantValidation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	cases := []struct {
		name string
		body string
	}{
		{"empty-body", `{}`},
		{"missing-handle", `{"did":"did:web:x"}`},
		{"missing-did", `{"handle":"x.example.com"}`},
		{"bad-did", `{"handle":"x.example.com","did":"not-a-did"}`},
		{"bad-json", `{`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := req(http.MethodPost, "/api/v1/admin/tenants", adminPrincipal())
			r.Body = io.NopCloser(strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			rec := do(h.Create, r)
			if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 4xx (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCreateTenantDuplicateHandle(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "dup.example.com", "did:web:dup.example.com")
	body := `{"handle":"dup.example.com","did":"did:web:other.example.com"}`
	r := req(http.MethodPost, "/api/v1/admin/tenants", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	rec := do(h.Create, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestDeleteTenant(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "del.example.com", "did:web:del.example.com")

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/tenants/del.example.com", adminPrincipal()))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if _, err := s.GetTenantByID(context.Background(), "t1"); err == nil {
		t.Fatal("tenant still present after delete")
	}
}

func TestDeleteTenantCascadesUsers(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "del.example.com", "did:web:del.example.com")
	if err := s.CreateUser(context.Background(), &store.User{ID: "u1", TenantID: "t1", Handle: "alice"}); err != nil {
		t.Fatal(err)
	}
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/tenants/del.example.com", adminPrincipal()))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if _, err := s.UserByID(context.Background(), "u1"); err == nil {
		t.Fatal("user not cascaded on tenant delete")
	}
}

func TestDeleteTenantNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/tenants/missing.example.com", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestNonAdminPrincipalForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "a.example.com", "did:web:a.example.com")

	// A non-admin principal must be rejected by the handler itself
	// (defense-in-depth), even though the scope middleware normally enforces it.
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/tenants", nonAdminPrincipal()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin list = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	rec2 := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/tenants/t1", nonAdminPrincipal()))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("non-admin get = %d, want 403", rec2.Code)
	}
	rec3 := do(h.Create, req(http.MethodPost, "/api/v1/admin/tenants", nonAdminPrincipal()))
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("non-admin create = %d, want 403", rec3.Code)
	}
	rec4 := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/tenants/a.example.com", nonAdminPrincipal()))
	if rec4.Code != http.StatusForbidden {
		t.Fatalf("non-admin delete = %d, want 403", rec4.Code)
	}
}

func TestUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/tenants", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}
