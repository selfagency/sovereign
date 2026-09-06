package ipfs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/selfagency/sovereign/internal/api/middleware"
	v1ipfs "github.com/selfagency/sovereign/internal/api/v1/admin/ipfs"
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

func newHandler(s *store.Store) *v1ipfs.Handler {
	return v1ipfs.New(s, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:ipfs:read", "admin:ipfs:write"}, IsAdmin: true}
}

func nonAdminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "user", TenantID: "tenant-a", Scopes: []string{"self"}, IsAdmin: false}
}

func req(method, path string, body []byte, p *middleware.Principal) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, http.NoBody)
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

const validCID = "QmYwAPJzv5CZsnAzt8auVZRnqBm4J5QhNn1JfGQ1tGq2cX"

func TestAddPin(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	body, _ := json.Marshal(map[string]string{"cid": validCID})
	rec := do(h.Add, req(http.MethodPost, "/api/v1/admin/ipfs/pins", body, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("add = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		CID    string `json:"cid"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.CID != validCID || out.Status != "pinned" {
		t.Fatalf("add = %+v", out)
	}
}

func TestAddPinRejectsInvalidCID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for _, cid := range []string{"not-a-cid", "", "Qm!!"} {
		body, _ := json.Marshal(map[string]string{"cid": cid})
		rec := do(h.Add, req(http.MethodPost, "/api/v1/admin/ipfs/pins", body, adminPrincipal()))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("add cid %q = %d, want 4xx", cid, rec.Code)
		}
	}
}

func TestAddPinNonAdminForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	body, _ := json.Marshal(map[string]string{"cid": validCID})
	rec := do(h.Add, req(http.MethodPost, "/api/v1/admin/ipfs/pins", body, nonAdminPrincipal()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("add non-admin = %d, want 403", rec.Code)
	}
}

func TestGetByCID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	if err := s.AddIPFSPin(context.Background(), validCID, "pinned"); err != nil {
		t.Fatal(err)
	}
	rec := do(h.GetByCID, req(http.MethodGet, "/api/v1/admin/ipfs/pins/"+validCID, nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestGetByCIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.GetByCID, req(http.MethodGet, "/api/v1/admin/ipfs/pins/"+validCID, nil, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404", rec.Code)
	}
}

func TestGetByCIDInvalid(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.GetByCID, req(http.MethodGet, "/api/v1/admin/ipfs/pins/not-a-cid", nil, adminPrincipal()))
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("get invalid = %d, want 4xx", rec.Code)
	}
}

func TestList(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	if err := s.AddIPFSPin(context.Background(), validCID, "pinned"); err != nil {
		t.Fatal(err)
	}
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/ipfs/pins", nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rec.Code)
	}
}
