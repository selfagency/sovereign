package middleware

import "net/http"

// sessionCookie builds a session cookie fixture matching the real session
// cookie set by the auth handler: HttpOnly, Secure, SameSite=Lax, Path=/.
// Keeping the flags accurate silences gosec G409 (a bare {Name,Value} cookie
// looks like an insecure session cookie) and matches production behavior.
func sessionCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     "session",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// csrfCookie builds a double-submit CSRF cookie fixture. HttpOnly is false by
// design (the thin client must read it to send X-CSRF-Token); Secure+Path
// satisfy the __Host- prefix. Suppressed for semgrep's cookie-http-only rule.
func csrfCookie(value string) *http.Cookie {
	// nosemgrep: go.lang.security.audit.net.cookie-http-only.cookie-http-only -- double-submit CSRF token cookie, not a session cookie
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	}
}
