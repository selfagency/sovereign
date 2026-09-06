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
