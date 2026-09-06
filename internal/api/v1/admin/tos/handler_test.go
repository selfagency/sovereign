package tos_test

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
	v1tos "github.com/selfagency/sovereign/internal/api/v1/admin/tos"
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

func newHandler(s *store.Store) *v1tos.Handler {
	return v1tos.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:system:read", "admin:system:write"}, IsAdmin: true}
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

func TestPutToS(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	body, _ := json.Marshal(map[string]string{"version": "v1", "content": "Terms content"})
	rec := do(h.Put, req(http.MethodPut, "/api/v1/admin/tos", body, adminPrincipal()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("put = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Version string `json:"version"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != "v1" || out.Content != "Terms content" {
		t.Fatalf("put = %+v", out)
	}
}

func TestPutToSValidation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for _, body := range []string{`{"version":"","content":"x"}`, `{"version":"v1","content":""}`, `not-json`} {
		rec := do(h.Put, req(http.MethodPut, "/api/v1/admin/tos", []byte(body), adminPrincipal()))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("put %q = %d, want 4xx", body, rec.Code)
		}
	}
}

func TestPutToSNonAdminForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	body, _ := json.Marshal(map[string]string{"version": "v1", "content": "x"})
	rec := do(h.Put, req(http.MethodPut, "/api/v1/admin/tos", body, nonAdminPrincipal()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("put non-admin = %d, want 403", rec.Code)
	}
}

func TestGetToS(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	if err := s.UpsertToSDocument(context.Background(), &store.ToSDocument{ID: "d1", Version: "v1", Content: "content"}); err != nil {
		t.Fatal(err)
	}
	rec := do(h.Get, req(http.MethodGet, "/api/v1/admin/tos", nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != "v1" {
		t.Fatalf("get = %+v", out)
	}
}

func TestGetToSNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Get, req(http.MethodGet, "/api/v1/admin/tos", nil, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get empty = %d, want 404", rec.Code)
	}
}
