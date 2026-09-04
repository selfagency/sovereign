package middleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"

	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// API audience constants for the control plane vs the protocol surfaces.
const (
	// API audience for the control-plane REST API. The RS/solid/atproto
	// audiences belong to other surfaces; the control plane requires this one.
	apiAudience = "sovereign-api"
)

// selfScopes are the coarse self-service scopes granted to a cookie (browser)
// principal. Session rows carry no scopes, so a cookie principal is granted
// this baseline; admin routes additionally require IsAdmin.
var selfScopes = []string{"self", "profile", "keys", "proofs", "sessions", "tokens", "export", "account"}

// adminScopes are the coarse admin scopes granted to a cookie principal whose
// user record has IsAdmin=true. They mirror the admin:* coarse scopes the
// scope-authz middleware enforces on admin routes.
var adminScopes = []string{
	"admin:tenants", "admin:users", "admin:clients", "admin:backup",
	"admin:moderation", "admin:audit", "admin:ipfs", "admin:system",
}

// SessionStore resolves an opaque session token hash to its row. It is
// implemented by *store.Store; an interface keeps the authn tests hermetic.
type SessionStore interface {
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*store.Session, error)
}

// UserStore resolves a user row by ID. Implemented by *store.Store.
type UserStore interface {
	UserByID(ctx context.Context, id string) (*store.User, error)
}

// AuthN authenticates each request via exactly one of two mutually exclusive
// credential paths:
//
//   - Bearer: an Authorization: Bearer <JWT> header, validated as an access
//     token against the API audience.
//   - Cookie: the HttpOnly session cookie, format-sniffed via
//     store.IsSessionToken. When DualRead is true, BOTH legacy JWT cookies
//     and new opaque session rows are accepted (same cookie name).
//
// A request carrying both a bearer header AND a session cookie is rejected
// (400), as is a cookie that somehow carries both the JWT and opaque shapes.
// The caller decides which routes need authentication: NewHandler wraps only
// non-anonymous route handlers with this middleware, so the authn decision is
// bound to the handler, not a path lookup.
type AuthN struct {
	Key           *rsa.PrivateKey // signing key for JWT validation
	Issuer        string          // identity issuer (https://id.<domain>)
	SessionCookie string          // cookie name (the shared "session")
	Sessions      SessionStore
	Users         UserStore
	DualRead      bool // accept both JWT cookies and session rows
}

var (
	errAmbiguous = errors.New("authn: ambiguous session credential")
	errUnauth    = errors.New("authn: unauthenticated")
)

// Middleware returns the authentication handler.
func (a *AuthN) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerToken(r.Header.Get("Authorization"))
		hasCookie := hasCookie(r, a.SessionCookie)
		if bearer != "" && hasCookie {
			// D-6: bearer and cookie are mutually exclusive.
			problem.InvalidRequest("bearer and cookie credentials are mutually exclusive").Write(w)
			return
		}

		var p *Principal
		var err error
		switch {
		case bearer != "":
			p, err = a.authenticateBearer(r, bearer)
		case hasCookie:
			p, err = a.authenticateCookie(r)
		default:
			err = errUnauth
		}
		if err != nil {
			if errors.Is(err, errAmbiguous) {
				problem.InvalidRequest("ambiguous session credential").Write(w)
				return
			}
			problem.Unauthenticated().Write(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// authenticateBearer validates a bearer credential. It accepts BOTH a legacy
// JWT access token (validated against the API audience) and an opaque
// server-side session token (resolved against the session store), so a token
// returned by the programmatic invite-redeem flow can be used as a Bearer
// credential. The credential is format-sniffed via store.IsSessionToken.
func (a *AuthN) authenticateBearer(r *http.Request, token string) (*Principal, error) {
	if store.IsSessionToken(token) {
		// Opaque session token as Bearer: resolve against the session store.
		// The principal is non-cookie, so refresh/delete (cookie-only) and CSRF
		// do not apply to it.
		return a.principalFromSession(r, token, false)
	}
	claims, err := auth.ValidateAccessToken(a.Key, token, a.Issuer, apiAudience)
	if err != nil {
		return nil, errUnauth
	}
	return a.principalFromSubject(r, claims.Subject, claims.Scopes, false)
}

// authenticateCookie format-sniffs the session cookie and authenticates either
// as a legacy JWT (when DualRead) or as an opaque session row.
func (a *AuthN) authenticateCookie(r *http.Request) (*Principal, error) {
	var jwtVal, opaqueVal string
	for _, c := range r.Cookies() {
		if c.Name != a.SessionCookie {
			continue
		}
		if store.IsSessionToken(c.Value) {
			opaqueVal = c.Value
		} else {
			jwtVal = c.Value
		}
	}
	// Both shapes in one request is ambiguous: reject, never guess.
	if jwtVal != "" && opaqueVal != "" {
		return nil, errAmbiguous
	}

	switch {
	case jwtVal != "":
		if !a.DualRead {
			// Legacy JWT cookies are retired once DualRead is flipped off.
			return nil, errUnauth
		}
		claims, err := auth.ValidateAccessToken(a.Key, jwtVal, a.Issuer, apiAudience)
		if err != nil {
			return nil, errUnauth
		}
		return a.principalFromSubject(r, claims.Subject, claims.Scopes, true)
	case opaqueVal != "":
		return a.principalFromSession(r, opaqueVal, true)
	default:
		return nil, errUnauth
	}
}

// principalFromSession resolves an opaque session token to its row, checks
// expiry/revocation, and builds the principal. isCookie distinguishes a
// browser (cookie) principal from a programmatic (bearer) one: a cookie
// session is granted self/admin scopes AND is subject to CSRF + refresh/delete;
// a bearer session is granted the same scopes but is not cookie-authenticated.
func (a *AuthN) principalFromSession(r *http.Request, token string, isCookie bool) (*Principal, error) {
	if a.Sessions == nil {
		return nil, errUnauth
	}
	sess, err := a.Sessions.GetSessionByTokenHash(r.Context(), store.HashSessionToken(token))
	if err != nil {
		return nil, errUnauth
	}
	if sess.IsExpired() || sess.RevokedAt != nil {
		return nil, errUnauth
	}
	if a.Users == nil {
		return nil, errUnauth
	}
	u, err := a.Users.UserByID(r.Context(), sess.UserID)
	if err != nil {
		return nil, errUnauth
	}
	// A session token always represents a logged-in user, so it carries the
	// self scopes (plus admin scopes when the user is an instance admin),
	// regardless of whether it arrived via cookie or bearer.
	scopes := selfScopes
	if u.IsAdmin {
		scopes = append(append([]string{}, adminScopes...), selfScopes...)
	}
	return &Principal{
		UserID:   u.ID,
		TenantID: u.TenantID,
		Scopes:   scopes,
		IsAdmin:  u.IsAdmin,
		IsCookie: isCookie,
	}, nil
}

// principalFromSubject loads the user row to derive tenant ID and admin flag.
// For a cookie principal the scopes are derived from the user record (admin
// gets the admin:* coarse scopes plus the self scopes; a non-admin gets only
// the self scopes), so a cookie-authenticated admin can reach admin:* routes.
// A bearer principal keeps whatever scopes its token granted.
func (a *AuthN) principalFromSubject(r *http.Request, userID string, scopes []string, isCookie bool) (*Principal, error) {
	if a.Users == nil {
		return nil, errUnauth
	}
	u, err := a.Users.UserByID(r.Context(), userID)
	if err != nil {
		return nil, errUnauth
	}
	if isCookie {
		scopes = selfScopes
		if u.IsAdmin {
			scopes = append(append([]string{}, adminScopes...), selfScopes...)
		}
	}
	return &Principal{
		UserID:   u.ID,
		TenantID: u.TenantID,
		Scopes:   scopes,
		IsAdmin:  u.IsAdmin,
		IsCookie: isCookie,
	}, nil
}

// bearerToken extracts the token from an Authorization header value, or "".
func bearerToken(authz string) string {
	const prefix = "Bearer "
	if len(authz) > len(prefix) && authz[:len(prefix)] == prefix {
		return authz[len(prefix):]
	}
	return ""
}

// hasCookie reports whether a request carries the named session cookie with a
// non-empty value. An empty/expired cookie value is treated as absent so a
// valid bearer credential is not rejected by a stale empty session cookie.
func hasCookie(r *http.Request, name string) bool {
	for _, c := range r.Cookies() {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
