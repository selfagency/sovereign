package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// cookiePrincipal returns a CSRF middleware whose IsCookiePrincipal is true.
func cookiePrincipal() *CSRF {
	return &CSRF{IsCookiePrincipal: func(*http.Request) bool { return true }}
}

// bearerPrincipal returns a CSRF middleware whose IsCookiePrincipal is false.
func bearerPrincipal() *CSRF {
	return &CSRF{IsCookiePrincipal: func(*http.Request) bool { return false }}
}

// okHandler is the downstream handler; it records that it was reached.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// withCSRFCookie attaches a __Host-csrf cookie to the request. Secure and
// Path are set to match SetToken; HttpOnly stays false (double-submit CSRF).
func withCSRFCookie(r *http.Request, token string) *http.Request {
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token, Path: "/", Secure: true, HttpOnly: false}) // #nosec G409 -- double-submit CSRF test fixture
	return r
}

// TestCSRFUnsafeNoToken verifies an unsafe method without a token is 403.
func TestCSRFUnsafeNoToken(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/data", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestCSRFHeaderToken verifies cookie + matching header token passes.
func TestCSRFHeaderToken(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "/data", http.NoBody), "tok")
	req.Header.Set(csrfHeaderName, "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestCSRFFormFieldToken verifies cookie + matching form-field token passes
// for form-encoded POSTs (the no-JS path).
func TestCSRFFormFieldToken(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	form := url.Values{csrfFieldName: {"tok"}}
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "/data", strings.NewReader(form.Encode())), "tok")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestCSRFMismatchedToken verifies a mismatched token is 403.
func TestCSRFMismatchedToken(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "/data", http.NoBody), "cookie-tok")
	req.Header.Set(csrfHeaderName, "other-tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestCSRFBearerPrincipal verifies a bearer principal skips CSRF.
func TestCSRFBearerPrincipal(t *testing.T) {
	h := bearerPrincipal().Middleware(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/data", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestCSRFSafeMethod verifies a safe method passes regardless of tokens.
func TestCSRFSafeMethod(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/data", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestCSRFCookieOnlyNoToken verifies a cookie without any submitted token is 403.
func TestCSRFCookieOnlyNoToken(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "/data", http.NoBody), "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestCSRFCrossOrigin verifies a cross-origin Origin on an unsafe method is 403.
func TestCSRFCrossOrigin(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "/data", http.NoBody), "tok")
	req.Header.Set(csrfHeaderName, "tok")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestCSRFSameOrigin verifies a same-origin Origin passes.
func TestCSRFSameOrigin(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "https://example.com/data", http.NoBody), "tok")
	req.Header.Set(csrfHeaderName, "tok")
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestCSRFSecFetchSiteCrossSite verifies Sec-Fetch-Site: cross-site is 403.
func TestCSRFSecFetchSiteCrossSite(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "/data", http.NoBody), "tok")
	req.Header.Set(csrfHeaderName, "tok")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestCSRFSecFetchSiteSameOrigin verifies Sec-Fetch-Site: same-origin passes.
func TestCSRFSecFetchSiteSameOrigin(t *testing.T) {
	h := cookiePrincipal().Middleware(okHandler())
	req := withCSRFCookie(httptest.NewRequest(http.MethodPost, "/data", http.NoBody), "tok")
	req.Header.Set(csrfHeaderName, "tok")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestSetToken verifies the cookie is set with Secure, Path=/, and readable.
func TestSetToken(t *testing.T) {
	rec := httptest.NewRecorder()
	SetToken(rec, "abc123")
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != csrfCookieName {
		t.Fatalf("name = %q, want %q", c.Name, csrfCookieName)
	}
	if c.Value != "abc123" {
		t.Fatalf("value = %q, want abc123", c.Value)
	}
	if !c.Secure {
		t.Fatal("cookie should be Secure")
	}
	if c.Path != "/" {
		t.Fatalf("path = %q, want /", c.Path)
	}
	if c.HttpOnly {
		t.Fatal("cookie should be readable by JS (HttpOnly=false)")
	}
	if c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite = %v, want Lax or Strict", c.SameSite)
	}
}

// TestNewToken verifies generated tokens are non-empty, unique, and base64url.
func TestNewToken(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || b == "" {
		t.Fatal("token should be non-empty")
	}
	if a == b {
		t.Fatal("tokens should be unique")
	}
	if len(a) < 22 { // 16 bytes -> 22 base64url chars
		t.Fatalf("token too short: %d chars", len(a))
	}
}
