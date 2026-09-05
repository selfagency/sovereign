// Package auth implements the /api/v1/auth/* control-plane endpoints: invite
// redemption, session lifecycle (get/refresh/revoke), and WebAuthn passkey
// registration/login. It is the migration target for the legacy magic-link
// inviteHandler and the handle-driven WebAuthn handlers.
package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// sessionTTL is the lifetime of a server-side session row. Sliding renewal
// (POST /auth/session/refresh) extends it.
const sessionTTL = 15 * time.Minute

// SessionCookie is the name of the HttpOnly session cookie holding the opaque
// server-side session token (shared with the legacy JWT cookie name so the
// dual-read authn middleware accepts both during migration).
const SessionCookie = "session"

// Handler serves the /api/v1/auth/* endpoints.
type Handler struct {
	store    *store.Store
	key      *rsa.PrivateKey
	issuer   string
	webauthn *auth.WebAuthnHandler
	logger   *slog.Logger
}

// New builds an auth Handler. The signing key and issuer are used only when
// minting/validating legacy JWT access tokens; new sessions are opaque
// server-side rows.
func New(st *store.Store, key *rsa.PrivateKey, issuer string, wh *auth.WebAuthnHandler, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, key: key, issuer: issuer, webauthn: wh, logger: logger}
}

// --- Invite redemption ---

// RedeemInvite exchanges an invite token for a NEW server-side session and
// returns the opaque session token once in the body (exchange-only: it is not
// set as a cookie). The client uses the token as a Bearer credential.
func (h *Handler) RedeemInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		problem.InvalidRequest("missing or invalid token").Write(w)
		return
	}
	sess, token, err := h.createInviteSession(r, req.Token)
	if err != nil {
		h.writeInviteError(w, err)
		return
	}
	// The raw token is show-once: it is persisted only as a hash.
	writeJSON(w, http.StatusOK, map[string]any{
		"session": sessionDTO(sess),
		"token":   token,
	})
}

// InviteGet is the ANONYMOUS browser entry point (M1). It redeems the token
// from the URL, creates a NEW server-side session, sets the opaque session
// cookie, and redirects to /panel.
//
// Token-in-URL leaks via Referer/access logs; this is acknowledged under the
// project's PII discipline: the token is single-use, short-lived, and its
// hash (not the raw value) is persisted, so a leaked URL cannot be replayed.
func (h *Handler) InviteGet(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/invite/")
	if raw == "" {
		problem.InvalidRequest("missing token").Write(w)
		return
	}
	sess, token, err := h.createInviteSession(r, raw)
	if err != nil {
		h.writeInviteError(w, err)
		return
	}
	h.setSessionCookie(w, token, sess.ExpiresAt)
	http.Redirect(w, r, "/panel", http.StatusSeeOther)
}

// createInviteSession redeems the invite token atomically, resolves the user,
// rejects deleted users, and creates a server-side session row. It returns
// the session and the raw (show-once) token.
func (h *Handler) createInviteSession(r *http.Request, raw string) (*store.Session, string, error) {
	ctx := r.Context()
	// Atomic single-use gate.
	if err := h.store.RedeemInviteToken(ctx, hashToken(raw), time.Now()); err != nil {
		return nil, "", err
	}
	it, err := h.store.InviteTokenByHash(ctx, hashToken(raw))
	if err != nil {
		return nil, "", err
	}
	// Reject tokens whose user was deleted: never mint a session for a
	// non-existent subject.
	if _, err := h.store.UserByID(ctx, it.UserID); err != nil {
		return nil, "", store.ErrInviteInvalid
	}
	token, err := store.GenerateSessionToken()
	if err != nil {
		return nil, "", err
	}
	sess, err := h.store.CreateSession(ctx, it.UserID, store.HashSessionToken(token), sessionTTL, uaHash(r), ipHash(r))
	if err != nil {
		return nil, "", err
	}
	return sess, token, nil
}

func (h *Handler) writeInviteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrInviteUsed), errors.Is(err, store.ErrInviteExpired):
		problem.Conflict().Write(w)
	case errors.Is(err, store.ErrInviteInvalid), errors.Is(err, store.ErrNotFound):
		problem.NotFound().Write(w)
	default:
		h.logger.Error("invite redemption failed", "err", err)
		problem.Internal().Write(w)
	}
}

// --- Session lifecycle ---

// GetSession returns the current principal as a typed DTO.
func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return
	}
	u, err := h.store.UserByID(r.Context(), p.UserID)
	if err != nil {
		problem.Unauthenticated().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, dto.Principal{
		UserID:      p.UserID,
		TenantID:    p.TenantID,
		Scopes:      p.Scopes,
		IsAdmin:     p.IsAdmin,
		IsCookie:    p.IsCookie,
		ToSAccepted: u.ToSAccepted,
	})
}

// RefreshSession performs sliding renewal: it touches the current session row
// (extends expires_at, updates last_seen_at) and returns the refreshed
// session. It requires a cookie principal (not a bearer token).
func (h *Handler) RefreshSession(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil || !p.IsCookie {
		problem.Unauthenticated().Write(w)
		return
	}
	token := h.sessionTokenFromCookie(r)
	if token == "" {
		problem.Unauthenticated().Write(w)
		return
	}
	sess, err := h.store.GetSessionByTokenHash(r.Context(), store.HashSessionToken(token))
	if err != nil {
		problem.Unauthenticated().Write(w)
		return
	}
	if sess.IsExpired() || sess.RevokedAt != nil {
		problem.Unauthenticated().Write(w)
		return
	}
	newExpiry := time.Now().UTC().Add(sessionTTL)
	if err := h.store.TouchSession(r.Context(), sess.ID, newExpiry); err != nil {
		problem.Internal().Write(w)
		return
	}
	// Return the refreshed session and re-set the cookie with the new expiry.
	sess.ExpiresAt = newExpiry
	h.setSessionCookie(w, token, newExpiry)
	writeJSON(w, http.StatusOK, sessionDTO(sess))
}

// DeleteSession revokes the current session and clears the cookie.
func (h *Handler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil || !p.IsCookie {
		problem.Unauthenticated().Write(w)
		return
	}
	token := h.sessionTokenFromCookie(r)
	if token == "" {
		problem.Unauthenticated().Write(w)
		return
	}
	sess, err := h.store.GetSessionByTokenHash(r.Context(), store.HashSessionToken(token))
	if err == nil {
		if err := h.store.RevokeSession(r.Context(), sess.ID); err != nil {
			problem.Internal().Write(w)
			return
		}
	}
	h.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// --- WebAuthn registration (session-derived user, B11) ---

// RegisterBegin returns WebAuthn registration options for the authenticated
// session's user. It IGNORES any ?handle= query param: the user is always the
// authenticated principal (B11 fix).
func (h *Handler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.principalUserID(w, r)
	if !ok {
		return
	}
	creation, _, err := h.webauthn.BeginRegistrationUser(userID)
	if err != nil {
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// RegisterFinish validates an attestation for the session's user, stores the
// credential, and marks passkey setup complete server-side.
func (h *Handler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.principalUserID(w, r)
	if !ok {
		return
	}
	if err := h.webauthn.FinishRegistrationUser(userID, r); err != nil {
		problem.InvalidRequest("registration failed").Write(w)
		return
	}
	if err := h.store.SetPasskeySetup(r.Context(), userID, true); err != nil {
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- WebAuthn login (anonymous, uniform) ---

// LoginBegin starts a discoverable (passkey) login and returns a uniform
// assertion response whose shape is identical whether or not the named handle
// exists, so an unknown handle cannot be enumerated. The handle is accepted
// but not used to look the user up.
func (h *Handler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, _, err := h.webauthn.BeginLoginUniform()
	if err != nil {
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// LoginFinish validates the assertion, resolves the user from the credential,
// creates a NEW server-side session, and sets the session cookie.
func (h *Handler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	userID, err := h.webauthn.FinishLoginUniform(r)
	if err != nil {
		problem.InvalidRequest("login failed").Write(w)
		return
	}
	token, err := store.GenerateSessionToken()
	if err != nil {
		problem.Internal().Write(w)
		return
	}
	sess, err := h.store.CreateSession(r.Context(), userID, store.HashSessionToken(token), sessionTTL, uaHash(r), ipHash(r))
	if err != nil {
		problem.Internal().Write(w)
		return
	}
	h.setSessionCookie(w, token, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionDTO(sess))
}

// --- helpers ---

// principalUserID returns the authenticated principal's user ID, or writes a
// 401 problem and returns ok=false.
func (h *Handler) principalUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return "", false
	}
	return p.UserID, true
}

// sessionTokenFromCookie returns the raw opaque session token from the cookie,
// or "".
func (h *Handler) sessionTokenFromCookie(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

// setSessionCookie sets the opaque session-token cookie: HttpOnly, Secure,
// SameSite=Lax, Path=/, named "session".
func (h *Handler) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

// clearSessionCookie expires the session cookie.
func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// sessionDTO renders a store session as a dto.Session.
func sessionDTO(s *store.Session) dto.Session {
	return dto.Session{
		ID:         s.ID,
		UserID:     s.UserID,
		CreatedAt:  s.CreatedAt,
		LastSeenAt: s.LastSeenAt,
		ExpiresAt:  s.ExpiresAt,
		RevokedAt:  s.RevokedAt,
	}
}

// uaHash returns the hex SHA-256 hash of the User-Agent header, or "".
func uaHash(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:])
}

// ipHash returns the hex SHA-256 hash of the client IP, or "".
func ipHash(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	if host == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(host))
	return hex.EncodeToString(sum[:])
}

// hashToken returns the hex SHA-256 hash of a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
