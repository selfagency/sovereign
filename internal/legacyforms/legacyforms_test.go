package legacyforms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

const (
	testIssuer   = "https://id.example.com"
	testAudience = "sovereign"
	testUserID   = "u1"
)

// harness wires a real store + RSA session key behind the CSRF middleware,
// mirroring how the adapter is mounted in production.
type harness struct {
	st      *store.Store
	handler http.Handler
	session *http.Cookie
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "legacyforms.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := st.CreateTenant(context.Background(), &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatalf("create tenant: %v", err)
	}
	if err := st.CreateUser(context.Background(), &store.User{ID: testUserID, TenantID: "identity", Handle: "alice"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	tok, err := auth.MintAccessToken(key, testUserID, nil, auth.AccessTokenTTL, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return &harness{
		st:      st,
		handler: (&middleware.CSRF{}).Middleware(NewHandler(st, key, testIssuer, testAudience)),
		session: &http.Cookie{Name: sessionCookie, Value: tok},
	}
}

// getForm performs an authenticated GET and returns the status code, the
// __Host-csrf cookie it set, and the body. Extra cookies (e.g. an existing
// csrf cookie) are sent along.
func (h *harness) getForm(t *testing.T, path string, extra ...*http.Cookie) (code int, csrf *http.Cookie, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	req.AddCookie(h.session)
	for _, c := range extra {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	body = rec.Body.String()
	_ = resp.Body.Close() // fully consumed into body; close immediately
	for _, c := range resp.Cookies() {
		if c.Name == csrfCookieName {
			csrf = c
		}
	}
	return resp.StatusCode, csrf, body
}

// post submits a form-encoded request with the given cookies.
func (h *harness) post(t *testing.T, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func TestNoJSToSAccept(t *testing.T) {
	h := newHarness(t)

	code, csrf, body := h.getForm(t, "/panel/tos")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/tos = %d, want 200", code)
	}
	if csrf == nil || csrf.Value == "" {
		t.Fatal("GET /panel/tos did not set a csrf cookie")
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Fatalf("ToS form missing hidden csrf_token field: %q", body)
	}
	if !strings.Contains(body, `value="`+csrf.Value+`"`) {
		t.Fatal("hidden csrf_token does not match the __Host-csrf cookie")
	}

	rec := h.post(t, "/panel/tos", url.Values{"csrf_token": {csrf.Value}, "accept": {"1"}}, h.session, csrf)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /panel/tos = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != panelPath {
		t.Fatalf("redirect = %q, want %q", loc, panelPath)
	}
	u, err := h.st.UserByID(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if !u.ToSAccepted {
		t.Fatal("ToS acceptance not recorded on the store")
	}
}

func TestNoJSProfileEdit(t *testing.T) {
	h := newHarness(t)

	code, csrf, body := h.getForm(t, "/panel/profile")
	if code != http.StatusOK {
		t.Fatalf("GET /panel/profile = %d, want 200", code)
	}
	if csrf == nil || csrf.Value == "" {
		t.Fatal("GET /panel/profile did not set a csrf cookie")
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Fatalf("profile form missing hidden csrf_token field: %q", body)
	}

	rec := h.post(t, "/panel/profile", url.Values{
		"csrf_token":   {csrf.Value},
		"display_name": {"  Alice  "},
		"bio":          {"  hello world  "},
	}, h.session, csrf)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /panel/profile = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != panelPath {
		t.Fatalf("redirect = %q, want %q", loc, panelPath)
	}
	page, err := h.st.GetProfilePage(context.Background(), "identity")
	if err != nil {
		t.Fatalf("GetProfilePage: %v", err)
	}
	if page.DisplayName != "Alice" || page.Bio != "hello world" {
		t.Fatalf("profile = %q/%q, want trimmed Alice/hello world", page.DisplayName, page.Bio)
	}

	// A second GET reuses the existing __Host-csrf cookie (no rotation) and
	// prefills the saved profile values.
	_, csrf2, body2 := h.getForm(t, "/panel/profile", csrf)
	if csrf2 != nil {
		t.Fatalf("GET /panel/profile rotated the csrf cookie: %q", csrf2.Value)
	}
	if !strings.Contains(body2, `value="Alice"`) || !strings.Contains(body2, "hello world") {
		t.Fatalf("profile form not prefilled: %q", body2)
	}
}

func TestNoJSCSRFRejected(t *testing.T) {
	h := newHarness(t)
	_, csrf, _ := h.getForm(t, "/panel/tos")

	t.Run("missing token", func(t *testing.T) {
		rec := h.post(t, "/panel/tos", url.Values{"accept": {"1"}}, h.session)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST without token = %d, want 403", rec.Code)
		}
	})
	t.Run("mismatched token", func(t *testing.T) {
		rec := h.post(t, "/panel/tos", url.Values{"csrf_token": {"not-the-cookie"}, "accept": {"1"}}, h.session, csrf)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST with mismatched token = %d, want 403", rec.Code)
		}
	})
}

func TestNoJSUnauthenticated(t *testing.T) {
	h := newHarness(t)
	// A valid csrf cookie so the failure is authentication, not CSRF.
	_, csrf, _ := h.getForm(t, "/panel/tos")

	rec := h.post(t, "/panel/tos", url.Values{"csrf_token": {csrf.Value}, "accept": {"1"}}, csrf)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/panel/profile", http.NoBody)
	rec = httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d, want 401", rec.Code)
	}

	// An invalid session cookie fails closed the same way.
	bad := httptest.NewRequest(http.MethodGet, "/panel/tos", http.NoBody)
	bad.AddCookie(&http.Cookie{Name: sessionCookie, Value: "not-a-jwt"})
	rec = httptest.NewRecorder()
	h.handler.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid-session GET = %d, want 401", rec.Code)
	}
}

func TestNoJSMethodNotAllowed(t *testing.T) {
	h := newHarness(t)
	_, csrf, _ := h.getForm(t, "/panel/tos")

	// PUT passes CSRF via the header path, then the handler rejects it.
	req := httptest.NewRequest(http.MethodPut, "/panel/tos", http.NoBody)
	req.AddCookie(h.session)
	req.AddCookie(csrf)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /panel/tos = %d, want 405", rec.Code)
	}
}
