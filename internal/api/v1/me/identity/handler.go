// Package identity implements the /api/v1/me/identity* self-service endpoints:
// read/update the authenticated principal's identity record, report onboarding
// state, accept the Terms of Service, request account deletion, and export the
// user's data. Every handler derives the subject from the authenticated
// principal in the request context; it never accepts a target user ID from the
// client, so a principal cannot read or mutate another user's identity.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/store"
)

// maxDisplayNameLen bounds the display-name length accepted on update.
const maxDisplayNameLen = 100

// Handler serves the /api/v1/me/identity* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds an identity Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// Onboarding is the typed onboarding-state response. It is derived from the
// user record (ToS acceptance, passkey setup) plus whether a profile page
// exists. Complete is true only when all three onboarding steps are done.
type Onboarding struct {
	ToSAccepted bool `json:"tos_accepted"`
	HasPasskey  bool `json:"has_passkey"`
	HasProfile  bool `json:"has_profile"`
	Complete    bool `json:"complete"`
}

// Export is the self-export payload: the user's full data set scoped to their
// tenant. It is streamed as a single JSON document.
type Export struct {
	User    dto.User          `json:"user"`
	Profile *dto.ProfilePage  `json:"profile,omitempty"`
	Links   []dto.ProfileLink `json:"links"`
	Keys    []dto.PublicKey   `json:"keys"`
	Proofs  []dto.ProofClaim  `json:"proofs"`
}

// updateReq is the PATCH body for updating self identity. Pointer fields
// distinguish an omitted field from an explicit empty value.
type updateReq struct {
	Email       *string `json:"email"`
	DisplayName *string `json:"display_name"`
}

// Get returns the authenticated principal's identity as a typed dto.User.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, userDTO(u))
}

// Update applies the requested identity mutations (email, display_name) using
// PATCH semantics: omitted fields are left unchanged, present fields are
// validated then persisted. At least one field must be present.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	var req updateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	if req.Email == nil && req.DisplayName == nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "body", Code: "empty", Detail: "at least one of email, display_name is required"}}).Write(w)
		return
	}
	ctx := r.Context()
	if !h.applyIdentityUpdate(w, ctx, u.ID, req) {
		return
	}
	updated, err := h.store.UserByID(ctx, u.ID)
	if err != nil {
		h.writeStoreErr(w, err, "reload user")
		return
	}
	writeJSON(w, http.StatusOK, userDTO(updated))
}

// OnboardingState reports the principal's onboarding progress.
func (h *Handler) OnboardingState(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	_, err := h.store.GetProfilePage(ctx, u.TenantID)
	hasProfile := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.logger.Error("onboarding: get profile", "err", err)
		problem.Internal().Write(w)
		return
	}
	onb := Onboarding{
		ToSAccepted: u.ToSAccepted,
		HasPasskey:  u.PasskeySetup,
		HasProfile:  hasProfile,
		Complete:    u.ToSAccepted && u.PasskeySetup && hasProfile,
	}
	writeJSON(w, http.StatusOK, onb)
}

// AcceptToS records that the principal accepted the current Terms of Service.
// It is idempotent: accepting an already-accepted ToS is a no-op.
func (h *Handler) AcceptToS(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	if err := h.store.SetToSAccepted(r.Context(), u.ID, true); err != nil {
		h.writeStoreErr(w, err, "accept tos")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"tos_accepted": true})
}

// RequestDeletion creates a pending-deletion request for the principal. It does
// NOT delete the account: the user stays usable until an admin approves the
// request (M2). Returns the pending request as a dto.PendingDeletion.
func (h *Handler) RequestDeletion(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	p, err := h.store.CreatePendingDeletion(r.Context(), u.ID)
	if err != nil {
		h.writeStoreErr(w, err, "create pending deletion")
		return
	}
	writeJSON(w, http.StatusCreated, pendingDeletionDTO(p))
}

// Export streams the principal's user record plus their profile page, links,
// public keys, and proof claims as a single JSON document.
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	exp := Export{User: userDTO(u), Links: []dto.ProfileLink{}, Keys: []dto.PublicKey{}, Proofs: []dto.ProofClaim{}}

	if page, err := h.store.GetProfilePage(ctx, u.TenantID); err == nil {
		pdto := profilePageDTO(page)
		exp.Profile = &pdto
		if links, lerr := h.store.ListProfileLinks(ctx, page.ID); lerr == nil {
			for i := range links {
				l := &links[i]
				exp.Links = append(exp.Links, dto.ProfileLink{
					ID: l.ID, Label: l.Label, URL: l.URL, Position: l.Position, CreatedAt: l.CreatedAt,
				})
			}
		} else {
			h.logger.Error("export: list profile links", "err", lerr)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		h.logger.Error("export: get profile", "err", err)
	}

	if keys, err := h.store.ListPublicKeys(ctx, u.TenantID, ""); err == nil {
		for i := range keys {
			k := &keys[i]
			exp.Keys = append(exp.Keys, dto.PublicKey{
				ID: k.ID, UserID: k.AccountID, Type: k.KeyType, Fingerprint: k.Fingerprint,
				PublicKey: k.KeyMaterial, CreatedAt: k.CreatedAt, RevokedAt: k.RevokedAt,
			})
		}
	} else {
		h.logger.Error("export: list keys", "err", err)
	}

	if proofs, err := h.store.ListProofClaims(ctx, u.TenantID); err == nil {
		for i := range proofs {
			c := &proofs[i]
			exp.Proofs = append(exp.Proofs, dto.ProofClaim{
				ID: c.ID, UserID: c.AccountID, Type: c.AnchorType, Target: c.AnchorValue,
				Status: c.Status, CreatedAt: c.CreatedAt,
			})
		}
	} else {
		h.logger.Error("export: list proofs", "err", err)
	}

	writeJSON(w, http.StatusOK, exp)
}

// --- helpers ---

// applyIdentityUpdate validates and persists the present updateReq fields,
// writing a problem response and returning false on the first failure. It is
// extracted from Update to keep the handler's branching flat.
func (h *Handler) applyIdentityUpdate(w http.ResponseWriter, ctx context.Context, userID string, req updateReq) bool {
	if req.Email != nil {
		if err := validateEmail(*req.Email); err != nil {
			problem.ValidationFailed([]problem.FieldError{{Field: "email", Code: "invalid", Detail: err.Error()}}).Write(w)
			return false
		}
		if err := h.store.SetUserEmail(ctx, userID, strings.TrimSpace(*req.Email)); err != nil {
			h.writeStoreErr(w, err, "set user email")
			return false
		}
	}
	if req.DisplayName != nil {
		if err := validateDisplayName(*req.DisplayName); err != nil {
			problem.ValidationFailed([]problem.FieldError{{Field: "display_name", Code: "invalid", Detail: err.Error()}}).Write(w)
			return false
		}
		if err := h.store.SetUserDisplayName(ctx, userID, strings.TrimSpace(*req.DisplayName)); err != nil {
			h.writeStoreErr(w, err, "set user display name")
			return false
		}
	}
	return true
}

// self returns the authenticated principal's user record, or writes a 401/404
// problem and returns ok=false.
func (h *Handler) self(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return nil, false
	}
	u, err := h.store.UserByID(r.Context(), p.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem.NotFound().Write(w)
		} else {
			h.logger.Error("identity: load user", "err", err)
			problem.Internal().Write(w)
		}
		return nil, false
	}
	return u, true
}

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("identity: "+op, "err", err)
	problem.Internal().Write(w)
}

func validateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.New("email must not be empty")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address == "" || !strings.Contains(addr.Address, "@") {
		return errors.New("email must be a valid address")
	}
	return nil
}

func validateDisplayName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("display_name must not be empty")
	}
	if len(name) > maxDisplayNameLen {
		return errors.New("display_name exceeds maximum length")
	}
	return nil
}

func userDTO(u *store.User) dto.User {
	return dto.User{
		ID:          u.ID,
		TenantID:    u.TenantID,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		IsAdmin:     u.IsAdmin,
		TOSAccepted: u.ToSAccepted,
		CreatedAt:   u.CreatedAt,
	}
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

func pendingDeletionDTO(p *store.PendingDeletion) dto.PendingDeletion {
	return dto.PendingDeletion{
		ID:          p.ID,
		UserID:      p.UserID,
		RequestedAt: p.RequestedAt,
		Status:      p.Status,
		ApprovedBy:  p.ApprovedBy,
		ApprovedAt:  p.ApprovedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
