// Package sessions implements the /api/v1/me/sessions* self-service endpoints
// for the authenticated principal's server-side sessions: list, revoke one, and
// revoke all (except the current). Every handler derives the subject from the
// authenticated principal in the request context; a session ID is only ever
// resolved against the principal's own user, so a principal cannot revoke
// another user's session (IDOR boundary). Responses never expose token material
// or IP hashes: token_hash is absent from the DTO and ip_hash is left unset.
package sessions

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/me/sessions* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds a sessions Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// List returns the authenticated principal's sessions, oldest first. Token
// hashes and IP hashes are never included in the response.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.self(w, r)
	if !ok {
		return
	}
	sessions, err := h.store.ListUserSessions(r.Context(), userID)
	if err != nil {
		h.logger.Error("sessions: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.Session, 0, len(sessions))
	for i := range sessions {
		out = append(out, sessionDTO(&sessions[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// Revoke revokes a single session by ID, scoped to the authenticated principal.
// A session belonging to another user is indistinguishable from a missing one
// (404), so a principal cannot probe or revoke another user's session.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.self(w, r)
	if !ok {
		return
	}
	id, ok := sessionIDFromPath(w, r)
	if !ok {
		return
	}
	sess, err := h.store.GetSessionByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem.NotFound().Write(w)
		} else {
			h.logger.Error("sessions: get session", "err", err)
			problem.Internal().Write(w)
		}
		return
	}
	// Cross-user safety: only the owner may revoke. A foreign session is
	// reported as 404 (existence safety), never 403.
	if sess.UserID != userID {
		problem.NotFound().Write(w)
		return
	}
	if err := h.store.RevokeSession(r.Context(), id); err != nil {
		h.logger.Error("sessions: revoke", "err", err)
		problem.Internal().Write(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeAll revokes every active session for the authenticated principal except
// the current one. The current session is identified by the session cookie; a
// bearer (non-cookie) principal has no current session to preserve, so all of
// its sessions are revoked.
func (h *Handler) RevokeAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.self(w, r)
	if !ok {
		return
	}
	keepID := h.currentSessionID(r)
	if err := h.store.RevokeUserSessionsExcept(r.Context(), userID, keepID); err != nil {
		h.logger.Error("sessions: revoke all", "err", err)
		problem.Internal().Write(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// self returns the authenticated principal's user ID, or writes a 401 problem
// and returns ok=false.
func (h *Handler) self(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return "", false
	}
	return p.UserID, true
}

// sessionIDFromPath extracts the {id} segment from the request path. ServeMux
// populates PathValue when the route is registered with a {id} pattern; for
// direct handler invocation (tests) it falls back to the last path segment.
func sessionIDFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		id = seg[len(seg)-1]
	}
	if id == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return id, true
}

// currentSessionID resolves the current session row from the session cookie,
// returning its ID, or "" when the request carries no session cookie (e.g. a
// bearer principal). The cookie value is hashed and looked up; the raw token is
// never exposed.
func (h *Handler) currentSessionID(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		return ""
	}
	sess, err := h.store.GetSessionByTokenHash(r.Context(), store.HashSessionToken(c.Value))
	if err != nil {
		return ""
	}
	return sess.ID
}

// sessionDTO renders a store session as a dto.Session, omitting token_hash
// (absent from the DTO) and ip_hash (left unset) so no token material or IP
// hash is exposed.
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
