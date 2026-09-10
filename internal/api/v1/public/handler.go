// Package public implements the anonymous /api/v1/public/* endpoints: the
// tenant's published profile page, public keys, and verified proof claims.
//
// These are mirrors of the store-backed profile/keys/proofs data served by the
// authenticated /me/* handlers, but for unauthenticated consumers. The tenant
// is always derived from the request context (injected by the tenant
// middleware from the Host header), never from the URL path. Unpublished or
// missing profiles return a uniform 404 so a caller cannot distinguish an
// unpublished tenant from a nonexistent one (no enumeration).
package public

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// Handler serves the /api/v1/public/* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds a public Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// Profile returns the tenant's published profile page. Unpublished or missing
// profiles yield a uniform 404 (no enumeration).
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	page, err := h.store.GetProfilePage(r.Context(), t.ID)
	if err != nil || !page.IsPublished {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, profilePageDTO(page))
}

// Keys returns the tenant's active public keys (revoked keys excluded).
func (h *Handler) Keys(w http.ResponseWriter, r *http.Request) {
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	rows, err := h.store.ListPublicKeys(r.Context(), t.ID, "")
	if err != nil {
		h.logger.Error("public: keys", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]dto.PublicKey, 0, len(rows))
	for i := range rows {
		if rows[i].RevokedAt != nil {
			continue
		}
		out = append(out, publicKeyDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// Proofs returns the tenant's verified proof claims only (pending/failed
// claims are never exposed publicly).
func (h *Handler) Proofs(w http.ResponseWriter, r *http.Request) {
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	claims, err := h.store.VerifiedProofClaims(r.Context(), t.ID)
	if err != nil {
		h.logger.Error("public: proofs", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]dto.ProofClaim, 0, len(claims))
	for i := range claims {
		out = append(out, proofClaimDTO(&claims[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func profilePageDTO(p *store.ProfilePage) dto.ProfilePage {
	return dto.ProfilePage{
		ID:          p.ID,
		UserID:      p.AccountID,
		DisplayName: p.DisplayName,
		Bio:         p.Bio,
		AvatarURL:   p.AvatarBlobKey,
		IsPublished: p.IsPublished,
		UpdatedAt:   p.UpdatedAt,
	}
}

func publicKeyDTO(k *store.PublicKey) dto.PublicKey {
	return dto.PublicKey{
		ID:          k.ID,
		UserID:      k.AccountID,
		Type:        k.KeyType,
		Fingerprint: k.Fingerprint,
		PublicKey:   k.KeyMaterial,
		CreatedAt:   k.CreatedAt,
		RevokedAt:   k.RevokedAt,
	}
}

func proofClaimDTO(c *store.ProofClaim) dto.ProofClaim {
	return dto.ProofClaim{
		ID:        c.ID,
		UserID:    c.AccountID,
		Type:      c.AnchorType,
		Target:    c.AnchorValue,
		Status:    c.Status,
		CreatedAt: c.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
