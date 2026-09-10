package moderation_test

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

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1moderation "github.com/selfagency/sovereign/internal/api/v1/admin/moderation"
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

func newHandler(s *store.Store) *v1moderation.Handler {
	return v1moderation.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal(tenantID string) *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: tenantID, Scopes: []string{"admin:moderation:read", "admin:moderation:write"}, IsAdmin: true}
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

func createTakedown(t *testing.T, h *v1moderation.Handler, p *middleware.Principal, resource, reason string) dto.Takedown {
	t.Helper()
	body := `{"resource":"` + resource + `","reason":"` + reason + `"}`
	r := req(http.MethodPost, "/api/v1/admin/moderation/takedowns", p)
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Create, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	return decode[dto.Takedown](t, rec)
}

func TestListTakedowns(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")
	createTakedown(t, h, adminPrincipal("tenant-a"), "res-2", "abuse")

	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/moderation/takedowns?limit=10&offset=0", adminPrincipal("tenant-a")))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.List[dto.Takedown]](t, rec)
	if got.Total != 2 || len(got.Data) != 2 {
		t.Fatalf("list = %+v, want 2/2", got)
	}
}

func TestListTakedownsPagination(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for i := 0; i < 3; i++ {
		createTakedown(t, h, adminPrincipal("tenant-a"), "res-"+string(rune('0'+i)), "spam")
	}
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/moderation/takedowns?limit=2&offset=0", adminPrincipal("tenant-a")))
	got := decode[dto.List[dto.Takedown]](t, rec)
	if got.Total != 3 || len(got.Data) != 2 {
		t.Fatalf("page1 = %+v, want total 3 len 2", got)
	}
	rec2 := do(h.List, req(http.MethodGet, "/api/v1/admin/moderation/takedowns?limit=2&offset=2", adminPrincipal("tenant-a")))
	got2 := decode[dto.List[dto.Takedown]](t, rec2)
	if len(got2.Data) != 1 {
		t.Fatalf("page2 = %+v, want len 1", got2)
	}
}

func TestListTakedownsInvalidPagination(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for _, q := range []string{"limit=abc", "limit=-1", "offset=xyz"} {
		rec := do(h.List, req(http.MethodGet, "/api/v1/admin/moderation/takedowns?"+q, adminPrincipal("tenant-a")))
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 4xx", q, rec.Code)
		}
	}
}

func TestCreateTakedown(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	got := createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")
	if got.Resource != "res-1" || got.Reason != "spam" || got.ID == "" {
		t.Fatalf("created takedown = %+v", got)
	}
	// Persisted and readable back.
	persisted, err := s.TakedownByID(context.Background(), got.ID)
	if err != nil || persisted.Resource != "res-1" {
		t.Fatalf("persisted: err=%v takedown=%+v", err, persisted)
	}
}

func TestCreateTakedownValidation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	cases := []struct {
		name string
		body string
	}{
		{"empty-body", `{}`},
		{"missing-resource", `{"reason":"spam"}`},
		{"missing-reason", `{"resource":"res-1"}`},
		{"blank-resource", `{"resource":"  ","reason":"spam"}`},
		{"bad-json", `{`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := req(http.MethodPost, "/api/v1/admin/moderation/takedowns", adminPrincipal("tenant-a"))
			r.Body = io.NopCloser(strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			rec := do(h.Create, r)
			if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 4xx (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestGetTakedownByID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	created := createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")

	rec := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/moderation/takedowns/"+created.ID, adminPrincipal("tenant-a")))
	if rec.Code != http.StatusOK {
		t.Fatalf("get by id = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.Takedown](t, rec)
	if got.ID != created.ID || got.Resource != "res-1" || got.Reason != "spam" {
		t.Fatalf("takedown = %+v", got)
	}
}

func TestGetTakedownByIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/moderation/takedowns/missing", adminPrincipal("tenant-a")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestDeleteTakedown(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	created := createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/moderation/takedowns/"+created.ID, adminPrincipal("tenant-a")))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if _, err := s.TakedownByID(context.Background(), created.ID); err == nil {
		t.Fatal("takedown still present after delete")
	}
}

func TestDeleteTakedownNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/moderation/takedowns/missing", adminPrincipal("tenant-a")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCreateWritesAuditWithActor(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")

	entries, err := s.ListAudit(context.Background(), "tenant-a", 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Actor != "admin" {
		t.Fatalf("actor = %q, want admin (A8 real actor)", e.Actor)
	}
	if e.Action != "takedown" || e.Target != "res-1" || e.Detail != "spam" {
		t.Fatalf("audit entry = %+v", e)
	}
}

func TestDeleteWritesAuditWithActor(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	created := createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/moderation/takedowns/"+created.ID, adminPrincipal("tenant-a")))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	entries, err := s.ListAudit(context.Background(), "tenant-a", 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit entries = %d, want 2 (create + delete)", len(entries))
	}
	// Newest first: the delete entry is first.
	if entries[0].Actor != "admin" || entries[0].Action != "takedown-lift" {
		t.Fatalf("delete audit entry = %+v, want actor admin action takedown-lift", entries[0])
	}
}

func TestNonAdminPrincipalForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	created := createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")

	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/moderation/takedowns", nonAdminPrincipal()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin list = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	rec2 := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/moderation/takedowns/"+created.ID, nonAdminPrincipal()))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("non-admin get = %d, want 403", rec2.Code)
	}
	rec3 := do(h.Create, req(http.MethodPost, "/api/v1/admin/moderation/takedowns", nonAdminPrincipal()))
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("non-admin create = %d, want 403", rec3.Code)
	}
	rec4 := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/moderation/takedowns/"+created.ID, nonAdminPrincipal()))
	if rec4.Code != http.StatusForbidden {
		t.Fatalf("non-admin delete = %d, want 403", rec4.Code)
	}
}

func TestUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/moderation/takedowns", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestNewNilLogger(t *testing.T) {
	s := testStore(t)
	h := v1moderation.New(s, nil)
	if h == nil {
		t.Fatal("New with nil logger returned nil handler")
	}
}

// TestListStoreError verifies a store failure surfaces as 500 (the internal
// error branch of writeStoreErr). The store is closed so queries fail.
func TestListStoreError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/moderation/takedowns", adminPrincipal("tenant-a")))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list store error = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCreateStoreError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	r := req(http.MethodPost, "/api/v1/admin/moderation/takedowns", adminPrincipal("tenant-a"))
	r.Body = io.NopCloser(strings.NewReader(`{"resource":"res-1","reason":"spam"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Create, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create store error = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestDeleteStoreError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/moderation/takedowns/some-id", adminPrincipal("tenant-a")))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete store error = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestCreateAuditError verifies that when the takedown write succeeds but the
// audit write fails, Create returns 500 (the audit-failure defensive branch).
// The audit_log table is dropped so only the audit write fails.
func TestCreateAuditError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	if _, err := s.DB().Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatalf("drop audit_log: %v", err)
	}
	r := req(http.MethodPost, "/api/v1/admin/moderation/takedowns", adminPrincipal("tenant-a"))
	r.Body = io.NopCloser(strings.NewReader(`{"resource":"res-1","reason":"spam"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Create, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create audit error = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestDeleteAuditError verifies that when the takedown delete succeeds but the
// audit write fails, Delete returns 500 (the audit-failure defensive branch).
func TestDeleteAuditError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	created := createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")
	if _, err := s.DB().Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatalf("drop audit_log: %v", err)
	}
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/moderation/takedowns/"+created.ID, adminPrincipal("tenant-a")))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete audit error = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestPathValueEmpty verifies a request with no path segment returns 404.
func TestPathValueEmpty(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.GetByID, req(http.MethodGet, "/", adminPrincipal("tenant-a")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty path = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestCrossTenantAuditIsolation verifies that a takedown performed by an
// admin acting on tenant A's context writes its audit entry scoped to tenant
// A, and is not visible via tenant B's audit log. Takedowns themselves are
// instance-scoped (no tenant column), so the cross-tenant boundary is enforced
// on the audit trail.
func TestCrossTenantAuditIsolation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	createTakedown(t, h, adminPrincipal("tenant-a"), "res-1", "spam")

	// Tenant A sees its own audit entry.
	entriesA, err := s.ListAudit(context.Background(), "tenant-a", 10)
	if err != nil {
		t.Fatalf("ListAudit A: %v", err)
	}
	if len(entriesA) != 1 {
		t.Fatalf("tenant A audit entries = %d, want 1", len(entriesA))
	}
	// Tenant B sees nothing.
	entriesB, err := s.ListAudit(context.Background(), "tenant-b", 10)
	if err != nil {
		t.Fatalf("ListAudit B: %v", err)
	}
	if len(entriesB) != 0 {
		t.Fatalf("tenant B audit entries = %d, want 0 (cross-tenant isolation)", len(entriesB))
	}
}
