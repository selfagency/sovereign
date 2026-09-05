// Package middleware provides HTTP middleware for the Sovereign API.
package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	// csrfCookieName is the double-submit CSRF cookie. The __Host- prefix
	// requires Secure, Path=/, and no Domain, which SetToken guarantees.
	csrfCookieName = "__Host-csrf"
	// csrfHeaderName is the header carrying the CSRF token for JS clients.
	csrfHeaderName = "X-CSRF-Token"
	// csrfFieldName is the hidden form field carrying the CSRF token for the
	// no-JS synchronizer-token fallback.
	csrfFieldName = "csrf_token"
)

// unsafeMethods are the request methods CSRF protects.
var unsafeMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// CSRF is double-submit CSRF middleware. It protects cookie-authenticated
// unsafe requests; bearer (programmatic) principals are exempt.
type CSRF struct {
	// IsCookiePrincipal reports whether the request is authenticated by a
	// cookie (as opposed to a bearer token). When false, CSRF is skipped.
	IsCookiePrincipal func(*http.Request) bool
}

// Middleware returns a handler enforcing CSRF on unsafe methods.
func (c *CSRF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !unsafeMethods[r.Method] {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer principals are mutually exclusive with cookies; skip CSRF.
		if c.IsCookiePrincipal != nil && !c.IsCookiePrincipal(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			http.Error(w, "csrf: cross-origin request rejected", http.StatusForbidden)
			return
		}
		if !validToken(r) {
			http.Error(w, "csrf: invalid or missing token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin enforces Origin and Sec-Fetch-Site on unsafe requests.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// validToken enforces the double-submit check: the cookie must be present and
// match a submitted token (header, or form field for form-encoded bodies).
func validToken(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	submitted := r.Header.Get(csrfHeaderName)
	if submitted == "" && isFormEncoded(r) {
		submitted = r.FormValue(csrfFieldName)
	}
	return submitted != "" && submitted == c.Value
}

// isFormEncoded reports whether the request body is form-urlencoded.
func isFormEncoded(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/x-www-form-urlencoded"
}

// SetToken sets the double-submit CSRF cookie. HttpOnly is false so JS can
// read it for the header path (double-submit pattern, see api.js); Secure and
// Path=/ satisfy the __Host- prefix. This is a CSRF token cookie, not a
// session cookie, so gosec G409 is a false positive.
func SetToken(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: false, // #nosec G409 -- double-submit CSRF; JS must read it, not a session cookie
		SameSite: http.SameSiteLaxMode,
	})
}

// NewToken returns a fresh CSRF token: 32 random bytes, base64url-encoded.
func NewToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(buf), "="), nil
}
