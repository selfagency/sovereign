package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/selfagency/sovereign/internal/api/dto"
)

// apiSrv boots a server wired to the control plane and returns it.
func apiSrv(t *testing.T, version string) *Server {
	t.Helper()
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, version)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// apiGet issues a GET against the identity host and returns the recorder.
func apiGet(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	req.Host = "id.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestServerBootServesAuthEndpoints verifies the auth/session endpoints are
// mounted (not 501 stubs) on the running server. An unauthenticated GET to
// /api/v1/auth/session must be 401 (authn enforced), not 501 (stub).
func TestServerBootServesAuthEndpoints(t *testing.T) {
	srv := apiSrv(t, "test")
	rec := apiGet(t, srv, "/api/v1/auth/session")
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("GET /api/v1/auth/session = 501 (stub not wired); want authn-enforced 401")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/auth/session = %d, want 401 (unauthenticated)", rec.Code)
	}
}

// TestServerBootServesAPIHealth verifies the server boots and serves
// /api/v1/health with a 200.
func TestServerBootServesAPIHealth(t *testing.T) {
	srv := apiSrv(t, "1.4.0")

	rec := apiGet(t, srv, "/api/v1/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/health = %d, want 200", rec.Code)
	}
	var h dto.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatalf("invalid health JSON: %v", err)
	}
	if h.Status != "ok" {
		t.Fatalf("health status = %q, want ok", h.Status)
	}
}

// TestAPISmokeHealth verifies the smoke path through the running server:
// /api/v1/health returns 200 with the ok body.
func TestAPISmokeHealth(t *testing.T) {
	srv := apiSrv(t, "dev")

	rec := apiGet(t, srv, "/api/v1/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got dto.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal health: %v", err)
	}
	if got.Status != "ok" {
		t.Fatalf("status field = %q, want ok", got.Status)
	}
}

// TestAPISmokeVersion verifies /api/v1/meta/version reports the build version
// passed to New(cfg, version).
func TestAPISmokeVersion(t *testing.T) {
	srv := apiSrv(t, "9.8.7")

	rec := apiGet(t, srv, "/api/v1/meta/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got dto.Version
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal version: %v", err)
	}
	if got.Version != "9.8.7" {
		t.Fatalf("version = %q, want 9.8.7", got.Version)
	}
	if got.GoVersion == "" {
		t.Fatal("go_version should be filled from runtime")
	}
}

// TestAPISmokeUnknownPath404 verifies an unknown /api/v1/ path is a 404.
func TestAPISmokeUnknownPath404(t *testing.T) {
	srv := apiSrv(t, "dev")

	rec := apiGet(t, srv, "/api/v1/nope/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestAPIReadyServes200 verifies /api/v1/ready returns 200 when the store is
// reachable (the store ping closure is wired).
func TestAPIReadyServes200(t *testing.T) {
	srv := apiSrv(t, "dev")

	rec := apiGet(t, srv, "/api/v1/ready")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestAPIOnIdentityHostOnly verifies /api/v1 is served on the identity host but
// not on tenant hosts (the control plane lives at id.<domain>/api/v1).
func TestAPIOnIdentityHostOnly(t *testing.T) {
	srv := apiSrv(t, "dev")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("/api/v1/health on tenant host = %d, want non-200", rec.Code)
	}
}
