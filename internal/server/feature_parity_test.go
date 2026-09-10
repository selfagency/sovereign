package server

// Feature-parity gate (T7.1): every function in the decommissioned HTTP
// layers must map to an API endpoint + client surface BEFORE deletion. This
// test enumerates the old surfaces and asserts each is covered by the REST
// API (internal/api/router.go) and the thin clients (internal/web/).
//
// The gate is intentionally a static assertion over the router + client
// sources: if a future refactor removes an endpoint or client surface, this
// test fails and the decommissioned function's coverage is re-checked.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFeatureParityGate asserts every legacy panel/admin function maps to a
// live API route and a client surface. It reads the router source and the
// embedded client sources directly so the gate cannot drift from reality.
func TestFeatureParityGate(t *testing.T) {
	root := repoRoot(t)

	routerSrc := readFile(t, filepath.Join(root, "internal", "api", "router.go"))
	panelJS := readFile(t, filepath.Join(root, "internal", "web", "panel", "panel.js"))
	adminJS := readFile(t, filepath.Join(root, "internal", "web", "admin", "admin.js"))
	legacyforms := readFile(t, filepath.Join(root, "internal", "legacyforms", "legacyforms.go"))

	// legacy panel.go surfaces → API + client coverage.
	panel := []struct {
		name    string
		apiPath string // route that must exist in router.go
		client  string // marker that must exist in a client source
	}{
		{"panelHandler (ToS view)", "/api/v1/me/tos", "/me/tos"},
		{"panelHandler (profile view)", "/api/v1/me/profile", "/me/profile"},
		{"panelHandler (passkey view)", "/api/v1/auth/webauthn/register/begin", "/auth/webauthn/register/begin"},
		{"sessionUser (session auth)", "/api/v1/me/onboarding", "/me/onboarding"},
		{"renderPanel (no-JS fallback)", "", "/panel/tos"},
	}
	for _, p := range panel {
		if p.apiPath != "" && !strings.Contains(routerSrc, `Path: "`+p.apiPath+`"`) {
			t.Errorf("parity: %s: API route %q missing from router", p.name, p.apiPath)
		}
		client := panelJS + adminJS + legacyforms
		if !strings.Contains(client, p.client) {
			t.Errorf("parity: %s: client surface %q missing", p.name, p.client)
		}
	}

	// internal/admin/users.go surfaces → API + client coverage.
	users := []struct {
		name    string
		apiPath string
		client  string
	}{
		{"UserHandler (create user)", "/api/v1/admin/users", "/admin/users"},
		{"UserHandler (send invite)", "/api/v1/admin/users/{id}/invites", "/invites"},
	}
	for _, u := range users {
		if !strings.Contains(routerSrc, `Path: "`+u.apiPath+`"`) {
			t.Errorf("parity: %s: API route %q missing from router", u.name, u.apiPath)
		}
		if !strings.Contains(adminJS, u.client) {
			t.Errorf("parity: %s: client surface %q missing from admin.js", u.name, u.client)
		}
	}

	// internal/admin/backup.go surfaces → API + client coverage.
	backup := []struct {
		name    string
		apiPath string
		client  string
	}{
		{"BackupHandler (config)", "/api/v1/admin/backup/config", "/admin/backup/config"},
		{"BackupHandler (run)", "/api/v1/admin/backup/runs", "/admin/backup/runs"},
		{"BackupHandler (restore)", "/api/v1/admin/backup/restores", "/admin/backup/restores"},
	}
	for _, b := range backup {
		if !strings.Contains(routerSrc, `Path: "`+b.apiPath+`"`) {
			t.Errorf("parity: %s: API route %q missing from router", b.name, b.apiPath)
		}
		if !strings.Contains(adminJS, b.client) {
			t.Errorf("parity: %s: client surface %q missing from admin.js", b.name, b.client)
		}
	}
}

// repoRoot walks up from the test file to the repository root (where go.mod
// lives).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above test working dir")
		}
		dir = parent
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
