package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// wantCSP is the exact strict policy every asset response must carry.
const wantCSP = "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// scriptTagRE matches an opening <script ...> tag.
var scriptTagRE = regexp.MustCompile(`(?i)<script\b[^>]*>`)

// rawFetchRE matches a direct fetch( call, which the panel must not make:
// every request goes through the shared api.js helper.
var rawFetchRE = regexp.MustCompile(`\bfetch\s*\(`)

func serve(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, http.NoBody))
	return rec
}

func TestAssetHandlerServesSharedFiles(t *testing.T) {
	h := Handler("/web/")
	cases := []struct {
		path   string
		ctype  string
		marker string
	}{
		{"/web/shared/api.js", "text/javascript; charset=utf-8", "class ApiError"},
		{"/web/shared/simple.css", "text/css; charset=utf-8", "--accent"},
		{"/web/panel/", "text/html; charset=utf-8", "<!doctype html>"},
		{"/web/panel/index.html", "text/html; charset=utf-8", "<!doctype html>"},
		{"/web/admin/", "text/html; charset=utf-8", "<!doctype html>"},
		{"/web/admin/index.html", "text/html; charset=utf-8", "<!doctype html>"},
		{"/web/admin/admin.js", "text/javascript; charset=utf-8", "import { api, ApiError }"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := serve(t, h, tc.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != tc.ctype {
				t.Errorf("Content-Type = %q, want %q", got, tc.ctype)
			}
			if !strings.Contains(rec.Body.String(), tc.marker) {
				t.Errorf("body missing marker %q", tc.marker)
			}
		})
	}
}

func TestAssetHandlerCSPIsStrict(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/shared/api.js")
	got := rec.Header().Get("Content-Security-Policy")
	if got != wantCSP {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, wantCSP)
	}
	// No loosening: no inline/eval, no external origins, no wildcard.
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "cdn.", "*"} {
		if strings.Contains(got, bad) {
			t.Errorf("CSP contains forbidden token %q: %q", bad, got)
		}
	}
	if ct := rec.Header().Get("X-Content-Type-Options"); ct != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", ct)
	}
	if xfo := rec.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", xfo)
	}
	if !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none': %q", got)
	}
}

// TestMountRootServesIndex asserts a handler mounted at a subtree root (e.g.
// /panel/ or /admin/) serves that directory's index.html for the bare root
// path — the invite and legacyforms redirects land on /panel, so a 404 here
// would break the onboarding flow.
func TestMountRootServesIndex(t *testing.T) {
	for _, prefix := range []string{"/panel/", "/admin/"} {
		h := Handler(prefix)
		rec := serve(t, h, prefix)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", prefix, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("GET %s Content-Type = %q, want text/html", prefix, ct)
		}
		if !strings.Contains(rec.Body.String(), "<!doctype html") {
			t.Errorf("GET %s body is not an HTML document", prefix)
		}
	}
}

func TestAssetHandlerCacheControl(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/shared/simple.css")
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("Cache-Control = %q, want a max-age directive", cc)
	}
}

func TestEmbeddedHTMLHasNoInlineScript(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/panel/index.html")
	html := rec.Body.String()
	if html == "" {
		t.Fatal("panel index.html served empty")
	}
	for _, tag := range scriptTagRE.FindAllString(html, -1) {
		if !strings.Contains(strings.ToLower(tag), "src=") {
			t.Errorf("inline <script> found: %q", tag)
		}
	}
	if strings.Contains(strings.ToLower(html), "javascript:") {
		t.Error("panel HTML contains a javascript: URL")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP permits inline script: %q", csp)
	}
}

func TestAPIClientImplementsContract(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/shared/api.js")
	js := rec.Body.String()
	for _, want := range []string{
		"__Host-csrf", "X-CSRF-Token", "Idempotency-Key", "If-None-Match",
		"class ApiError", "export const api",
		"/api/v1/auth/invite/redeem", "/api/v1/admin/backup/runs", "/api/v1/admin/backup/restores",
		"401", "403", "429",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("api.js missing %q", want)
		}
	}
}

func TestAssetHandlerRejectsTraversal(t *testing.T) {
	paths := []string{
		"/web/../server.go",
		"/web/../../etc/passwd",
		"/../server.go",
		"/shared/../../server.go",
	}
	for _, prefix := range []string{"/web/", ""} {
		h := Handler(prefix)
		for _, p := range paths {
			rec := serve(t, h, p)
			if rec.Code != http.StatusNotFound {
				t.Errorf("prefix %q path %q: status = %d, want 404", prefix, p, rec.Code)
			}
		}
	}
}

func TestAssetHandlerUnknownAsset(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/shared/missing.js")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestPanelIndexLoadsPanelModule asserts the panel shell boots the step machine
// as an external ES module and carries no inline script or removed passkey
// flag toggle.
func TestPanelIndexLoadsPanelModule(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/panel/index.html")
	html := rec.Body.String()
	if !strings.Contains(html, `type="module"`) {
		t.Error("panel index.html does not load a module script")
	}
	if !strings.Contains(html, `src="/web/panel/panel.js"`) {
		t.Error("panel index.html does not load panel.js as an external module")
	}
	if !strings.Contains(html, `href="/web/shared/simple.css"`) {
		t.Error("panel index.html does not link the vendored stylesheet")
	}
	if strings.Contains(html, "/panel/passkey") {
		t.Error("panel index.html still references the removed /panel/passkey flag toggle")
	}
}

// TestAdminIndexLoadsModule asserts the admin shell boots the client as an
// external ES module, links the vendored stylesheet, carries no inline script,
// and is served under the strict CSP.
func TestAdminIndexLoadsModule(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/admin/index.html")
	html := rec.Body.String()
	if !strings.Contains(html, `type="module"`) {
		t.Error("admin index.html does not load a module script")
	}
	if !strings.Contains(html, `src="/web/admin/admin.js"`) {
		t.Error("admin index.html does not load admin.js as an external module")
	}
	if !strings.Contains(html, `href="/web/shared/simple.css"`) {
		t.Error("admin index.html does not link the vendored stylesheet")
	}
	for _, tag := range scriptTagRE.FindAllString(html, -1) {
		if !strings.Contains(strings.ToLower(tag), "src=") {
			t.Errorf("inline <script> found: %q", tag)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != wantCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, wantCSP)
	}
}

// TestAdminModuleServesViews asserts admin.js is served as JavaScript and
// references every admin API route from the context file (the route smoke
// test): each view must reach its endpoints through the shared api.js, never
// raw fetch.
func TestAdminModuleServesViews(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/admin/admin.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/javascript; charset=utf-8", ct)
	}
	js := rec.Body.String()
	for _, want := range []string{
		`"../shared/api.js"`,
		// Dashboard.
		"/admin/system/info", "/meta/capabilities",
		// Tenants.
		"/admin/tenants",
		"/admin/tenants/${encodeURIComponent(id)}",
		"/admin/tenants/${encodeURIComponent(t.id)}",
		// Users: list/create, get/patch/delete, invite, credentials, revoke.
		"/admin/users",
		"/admin/users/${encodeURIComponent(id)}",
		"/admin/users/${encodeURIComponent(u.id)}",
		"/admin/users/${encodeURIComponent(id)}/invites",
		"/admin/users/${encodeURIComponent(id)}/credentials",
		"/admin/users/${encodeURIComponent(id)}/sessions:revoke",
		// Clients: list/create, delete, secret rotation.
		"/admin/clients",
		"/admin/clients/${encodeURIComponent(id)}",
		"/admin/clients/${encodeURIComponent(c.id)}",
		"/admin/clients/${encodeURIComponent(id)}/secret/rotate",
		// Backups: config, runs, restores.
		"/admin/backup/config", "/admin/backup/runs", "/admin/backup/restores",
		"/admin/backup/runs/${encodeURIComponent(id)}",
		// Moderation takedowns.
		"/admin/moderation/takedowns",
		"/admin/moderation/takedowns/${encodeURIComponent(id)}",
		"/admin/moderation/takedowns/${encodeURIComponent(t.id)}",
		// Audit log.
		"/admin/audit",
		// IPFS pins.
		"/admin/ipfs/pins",
		"/admin/ipfs/pins/${encodeURIComponent(cid)}",
		// Terms of Service.
		"/admin/tos",
		// Deletion requests: list, approve, reject.
		"/admin/deletion-requests",
		"/admin/deletion-requests/${encodeURIComponent(d.id)}/approve",
		"/admin/deletion-requests/${encodeURIComponent(d.id)}/reject",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("admin.js missing %q", want)
		}
	}
	if rawFetchRE.MatchString(js) {
		t.Error("admin.js uses raw fetch; it must go through the shared api.js")
	}
}

// TestPanelModuleServesSurfaces asserts panel.js is served as JavaScript and
// wires every required surface through the shared api.js (no raw fetch).
func TestPanelModuleServesSurfaces(t *testing.T) {
	rec := serve(t, Handler("/web/"), "/web/panel/panel.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/javascript; charset=utf-8", ct)
	}
	js := rec.Body.String()
	for _, want := range []string{
		`"../shared/api.js"`,
		"/me/onboarding",
		"/me/profile",
		"/me/profile/avatar",
		"/me/profile:${action}",
		"/me/profile/links",
		"/me/profile/links:reorder",
		"/me/keys",
		"/me/proofs",
		"/me/credentials",
		"/me/sessions",
		"/me/tokens",
		"/me/export",
		"/auth/webauthn/register/begin",
		"/auth/webauthn/register/finish",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("panel.js missing %q", want)
		}
	}
	if strings.Contains(js, "/panel/passkey") {
		t.Error("panel.js still references the removed /panel/passkey flag toggle")
	}
	if rawFetchRE.MatchString(js) {
		t.Error("panel.js uses raw fetch; it must go through the shared api.js")
	}
}
