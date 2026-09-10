// Package credentials implements the /api/v1/me/credentials* self-service
// endpoints for the authenticated principal's WebAuthn passkeys: list and
// delete. Every handler derives the subject from the authenticated principal
// in the request context; a credential is only ever resolved against the
// principal's own user, so a principal cannot list or delete another user's
// credential (IDOR boundary). Deleting a user's last passkey is refused with a
// 409 (store.ErrLastCredential). The go-webauthn credential Data (which can
// embed attestation material) is never served; only public identifiers and
// metadata are exposed.
package credentials

import (
	"encoding/base64"
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

// Handler serves the /api/v1/me/credentials* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds a credentials Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// List returns the authenticated principal's WebAuthn passkeys as public
// metadata only (never the go-webauthn credential Data or key material).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, ok := h.self(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListWebAuthnCredentials(r.Context(), p.UserID)
	if err != nil {
		h.logger.Error("credentials: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.WebAuthnCredential, 0, len(rows))
	for i := range rows {
		out = append(out, credentialDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// Delete removes one of the authenticated principal's passkeys by its internal
// credential row ID. Deleting the user's only passkey is refused with a 409
// (store.ErrLastCredential). A credential belonging to another user is
// indistinguishable from a missing one (404).
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.self(w, r)
	if !ok {
		return
	}
	id := credIDFromPath(w, r)
	if id == "" {
		return
	}
	// Resolve the credential by ID; only the owner may delete it. A foreign
	// credential is reported as 404 (existence safety).
	rows, err := h.store.ListWebAuthnCredentials(r.Context(), p.UserID)
	if err != nil {
		h.logger.Error("credentials: delete: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	var credID []byte
	found := false
	for i := range rows {
		if rows[i].ID == id {
			credID = rows[i].CredentialID
			found = true
			break
		}
	}
	if !found {
		problem.NotFound().Write(w)
		return
	}
	if err := h.store.DeleteWebAuthnCredential(r.Context(), p.UserID, credID); err != nil {
		switch {
		case errors.Is(err, store.ErrLastCredential):
			problem.Conflict().Write(w)
		case errors.Is(err, store.ErrNotFound):
			problem.NotFound().Write(w)
		default:
			h.logger.Error("credentials: delete", "err", err)
			problem.Internal().Write(w)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

// credentialDTO renders a store WebAuthnCredential as its wire DTO. The
// go-webauthn Data and PublicKey are never exposed; only the credential ID
// (base64url) and metadata are.
func credentialDTO(c *store.WebAuthnCredential) dto.WebAuthnCredential {
	return dto.WebAuthnCredential{
		ID:           c.ID,
		CredentialID: base64.RawURLEncoding.EncodeToString(c.CredentialID),
		CreatedAt:    c.CreatedAt,
	}
}

// credIDFromPath extracts the {id} segment from the request path. ServeMux
// populates PathValue when the route is registered with a {id} pattern; for
// direct handler invocation (tests) it falls back to the last path segment.
func credIDFromPath(w http.ResponseWriter, r *http.Request) string {
	id := r.PathValue("id")
	if id == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		id = seg[len(seg)-1]
	}
	if id == "" {
		problem.NotFound().Write(w)
	}
	return id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
