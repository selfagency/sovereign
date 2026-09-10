package audit_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/v1/admin/audit"
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

func newHandler(s *store.Store) *audit.Handler {
	return audit.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:audit"}, IsAdmin: true}
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

func TestAuditList(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	ctx := t.Context()
	// Seed audit entries across two tenants (instance-scoped).
	for _, e := range []*store.AuditEntry{
		{ID: "a1", TenantID: "t1", Actor: "admin1", Action: "takedown", Target: "res1", Detail: "d1", CreatedAt: time.Now().Add(-time.Minute)},
		{ID: "a2", TenantID: "t2", Actor: "admin2", Action: "deletion.approve", Target: "res2", Detail: "d2", CreatedAt: time.Now()},
	} {
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/audit?limit=10&offset=0", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.List[dto.AuditEntry]](t, rec)
	if got.Total != 2 || len(got.Data) != 2 {
		t.Fatalf("list = %+v, want 2/2", got)
	}
	// The actor is the real principal (A8).
	seen := map[string]bool{}
	for _, e := range got.Data {
		seen[e.Actor] = true
	}
	if !seen["admin1"] || !seen["admin2"] {
		t.Fatalf("actors = %v, want admin1+admin2", seen)
	}
}

func TestAuditNonAdminForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/audit", nonAdminPrincipal()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin = %d, want 403", rec.Code)
	}
}

func TestAuditUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/audit", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestAuditInvalidPagination(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for _, q := range []string{"limit=-1", "offset=-1", "limit=abc"} {
		rec := do(h.List, req(http.MethodGet, "/api/v1/admin/audit?"+q, adminPrincipal()))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("q=%q = %d, want 422", q, rec.Code)
		}
	}
}
