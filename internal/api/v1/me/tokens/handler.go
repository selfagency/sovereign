// Package tokens implements the /api/v1/me/tokens* self-service endpoints for
// the authenticated principal's programmatic API tokens: create (show-once:
// the raw token is returned exactly once, never re-readable), list (metadata
// only, never the token), and revoke one family. Every handler derives the
// subject from the authenticated principal in the request context; a token is
// only ever resolved against the principal's own user, so a principal cannot
// read or revoke another user's token (IDOR boundary). Responses never expose
// raw token material: token_hash is absent from the DTO.
package tokens

import (
	"crypto/rand"
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
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/wiring"
)

// Handler serves the /api/v1/me/tokens* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds a tokens Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// createReq is the body for creating a programmatic token. Scopes selects the
// subset of the principal's granted scopes the token carries; Name is an
// optional human label.
type createReq struct {
	Scopes []string `json:"scopes"`
	Name   string   `json:"name"`
}

// Create mints a new programmatic token for the authenticated principal. The
// raw token is returned exactly once in the response (show-once); only its
// hash is persisted, so it is never re-readable. The requested scope subset is
// validated against the principal's granted scopes; requesting a scope the
// principal does not hold is a 422.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := h.self(w, r)
	if !ok {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	// Scope-subset selection: every requested scope must be one the principal
	// is granted (exact match). An empty selection defaults to none.
	for _, s := range req.Scopes {
		if !wiring.ScopesContains(p.Scopes, s) {
			problem.ValidationFailed([]problem.FieldError{{
				Field: "scopes", Code: "not_granted",
				Detail: "requested scope is not among the principal's granted scopes: " + s,
			}}).Write(w)
			return
		}
	}
	if len(req.Scopes) == 0 {
		problem.ValidationFailed([]problem.FieldError{{
			Field: "scopes", Code: "required",
			Detail: "at least one scope is required",
		}}).Write(w)
		return
	}

	raw, err := store.GenerateAPIToken()
	if err != nil {
		h.logger.Error("tokens: generate", "err", err)
		problem.Internal().Write(w)
		return
	}
	now := time.Now().UTC()
	tok := &store.APIToken{
		ID:        newTokenID(),
		UserID:    p.UserID,
		TokenHash: store.HashAPIToken(raw),
		FamilyID:  newTokenID(),
		Name:      strings.TrimSpace(req.Name),
		Scopes:    req.Scopes,
		CreatedAt: now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
	}
	if err := h.store.CreateAPIToken(r.Context(), tok); err != nil {
		h.logger.Error("tokens: create", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, dto.APITokenCreateResponse{
		APIToken: *tokenDTO(tok),
		Token:    raw,
	})
}

// List returns the authenticated principal's programmatic tokens as metadata
// only (never the token value or its hash), oldest first.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, ok := h.self(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListAPITokens(r.Context(), p.UserID)
	if err != nil {
		h.logger.Error("tokens: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.APIToken, 0, len(rows))
	for i := range rows {
		out = append(out, *tokenDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// Revoke revokes a single programmatic token family by ID, scoped to the
// authenticated principal. A token belonging to another user is
// indistinguishable from a missing one (404).
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	p, ok := h.self(w, r)
	if !ok {
		return
	}
	id := familyIDFromPath(w, r)
	if id == "" {
		return
	}
	if err := h.store.RevokeAPITokenFamily(r.Context(), p.UserID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem.NotFound().Write(w)
		} else {
			h.logger.Error("tokens: revoke", "err", err)
			problem.Internal().Write(w)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// familyIDFromPath extracts the {family_id} segment from the request path.
// ServeMux populates PathValue when the route is registered with a
// {family_id} pattern; for direct handler invocation (tests) it falls back to
// the last path segment.
func familyIDFromPath(w http.ResponseWriter, r *http.Request) string {
	id := r.PathValue("family_id")
	if id == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		id = seg[len(seg)-1]
	}
	if id == "" {
		problem.NotFound().Write(w)
	}
	return id
}

// --- helpers ---

// self returns the authenticated principal's user ID, or writes a 401 problem
// and returns ok=false.
func (h *Handler) self(w http.ResponseWriter, r *http.Request) (*middleware.Principal, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return nil, false
	}
	return p, true
}

// tokenDTO renders a store APIToken as its wire DTO, omitting token hash and
// the raw token (both are secret; the raw token is show-once at creation).
func tokenDTO(t *store.APIToken) *dto.APIToken {
	d := &dto.APIToken{
		ID:         t.ID,
		FamilyID:   t.FamilyID,
		Name:       t.Name,
		Scopes:     t.Scopes,
		CreatedAt:  t.CreatedAt,
		LastUsedAt: t.LastUsedAt,
	}
	if !t.ExpiresAt.IsZero() {
		exp := t.ExpiresAt
		d.ExpiresAt = &exp
	}
	return d
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// newTokenID returns a new random hex token/family ID (16 bytes).
func newTokenID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("tokens: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}
