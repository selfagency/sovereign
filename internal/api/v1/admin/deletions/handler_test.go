package deletions_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1deletions "github.com/selfagency/sovereign/internal/api/v1/admin/deletions"
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

func newHandler(s *store.Store) *v1deletions.Handler {
	return v1deletions.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:users"}, IsAdmin: true}
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

// actionReq builds a request for an approve/reject action with the path value
// set, mimicking what ServeMux would set for {id}.
func actionReq(method, path, id string, p *middleware.Principal) *http.Request {
	r := req(method, path, p)
	r.SetPathValue("id", id)
	return r
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v (body %s)", v, err, rec.Body.String())
	}
	return v
}

func seedTenant(t *testing.T, s *store.Store, id, handle string) {
	t.Helper()
	if err := s.CreateTenant(t.Context(), &store.Tenant{ID: id, Handle: handle, DIDMethod: "web"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
}

func seedUser(t *testing.T, s *store.Store, id, tenantID, handle string) {
	t.Helper()
	if err := s.CreateUser(t.Context(), &store.User{ID: id, TenantID: tenantID, Handle: handle, Email: handle + "@x.test"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

func TestDeletionsList(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "t1.example.com")
	seedUser(t, s, "u1", "t1", "alice")
	seedUser(t, s, "u2", "t1", "bob")
	p1, err := s.CreatePendingDeletion(t.Context(), "u1")
	if err != nil {
		t.Fatalf("CreatePendingDeletion: %v", err)
	}
	if _, err := s.CreatePendingDeletion(t.Context(), "u2"); err != nil {
		t.Fatalf("CreatePendingDeletion u2: %v", err)
	}

	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/deletion-requests?limit=10&offset=0", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.List[dto.PendingDeletion]](t, rec)
	if got.Total != 2 || len(got.Data) != 2 {
		t.Fatalf("list = %+v, want 2/2", got)
	}
	// Round-trips the id.
	if got.Data[0].ID != p1.ID && got.Data[1].ID != p1.ID {
		t.Fatalf("list missing %s", p1.ID)
	}
}

func TestDeletionsApproveCascadesDelete(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "t1.example.com")
	seedUser(t, s, "u1", "t1", "alice")
	p, err := s.CreatePendingDeletion(t.Context(), "u1")
	if err != nil {
		t.Fatalf("CreatePendingDeletion: %v", err)
	}

	rec := do(h.Approve, actionReq(http.MethodPost, "/api/v1/admin/deletion-requests/"+p.ID+"/approve", p.ID, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.PendingDeletion](t, rec)
	if got.Status != "approved" || got.ApprovedBy == nil || *got.ApprovedBy != "admin" {
		t.Fatalf("approved = %+v", got)
	}
	// User cascade-deleted.
	if _, err := s.UserByID(t.Context(), "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user still present after approve (got %v)", err)
	}
}

func TestDeletionsRejectNoOp(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	seedTenant(t, s, "t1", "t1.example.com")
	seedUser(t, s, "u1", "t1", "alice")
	p, err := s.CreatePendingDeletion(t.Context(), "u1")
	if err != nil {
		t.Fatalf("CreatePendingDeletion: %v", err)
	}

	rec := do(h.Reject, actionReq(http.MethodPost, "/api/v1/admin/deletion-requests/"+p.ID+"/reject", p.ID, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("reject = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.PendingDeletion](t, rec)
	if got.Status != "rejected" {
		t.Fatalf("rejected = %+v", got)
	}
	// Account intact.
	if _, err := s.UserByID(t.Context(), "u1"); err != nil {
		t.Fatalf("reject must not delete the user: %v", err)
	}
}

func TestDeletionsApproveNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Approve, req(http.MethodPost, "/api/v1/admin/deletion-requests/missing/approve", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("approve missing = %d, want 404", rec.Code)
	}
}

func TestDeletionsNonAdminForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for name, fn := range map[string]http.HandlerFunc{
		"list":    h.List,
		"approve": h.Approve,
		"reject":  h.Reject,
	} {
		rec := do(fn, req(http.MethodGet, "/api/v1/admin/deletion-requests", nonAdminPrincipal()))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s non-admin = %d, want 403", name, rec.Code)
		}
	}
}
