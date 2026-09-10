package system_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/v1/admin/system"
)

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:system"}, IsAdmin: true}
}

func nonAdminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "user", TenantID: "tenant-a", Scopes: []string{"self"}, IsAdmin: false}
}

func req(path string, p *middleware.Principal) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	if p != nil {
		r = r.WithContext(middleware.WithPrincipal(r.Context(), p))
	}
	return r
}

func TestSystemInfo(t *testing.T) {
	h := system.New(&system.Info{
		Domain:            "example.com",
		Audience:          "example.com",
		DataDir:           "/var/lib/sovereign",
		OpenRegistrations: true,
		StorageBackend:    "fs",
		IPFSEnabled:       false,
		SMTPEnabled:       true,
		SMTPHost:          "smtp.example.com",
		SMTPFrom:          "noreply@example.com",
		APICORSOrigins:    []string{"https://app.example.com"},
	})
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.Info).ServeHTTP(rec, req("/api/v1/admin/system/info", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("info = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["domain"] != "example.com" || body["storage_backend"] != "fs" {
		t.Fatalf("info = %+v", body)
	}
	// Secrets must be absent: no smtp password, no s3 access/secret keys.
	for _, secret := range []string{"password", "access_key", "secret_key"} {
		if _, present := body[secret]; present {
			t.Fatalf("secret %q leaked in system/info: %+v", secret, body)
		}
	}
}

func TestSystemInfoNonAdminForbidden(t *testing.T) {
	h := system.New(&system.Info{})
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.Info).ServeHTTP(rec, req("/api/v1/admin/system/info", nonAdminPrincipal()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin = %d, want 403", rec.Code)
	}
}

func TestSystemInfoUnauthenticated(t *testing.T) {
	h := system.New(&system.Info{})
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.Info).ServeHTTP(rec, req("/api/v1/admin/system/info", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}
