// Package keys implements the /api/v1/me/keys* self-service endpoints for the
// authenticated principal's public keys: list, get, create, delete, and revoke.
// Every handler derives the tenant and account from the authenticated principal
// in the request context; it never accepts a target tenant, account, or key ID
// belonging to another user from the client, so a principal cannot read or
// mutate another tenant's keys (IDOR boundary). Key material is validated and
// canonicalized through the internal/keys parser, which refuses private-key
// material fail-closed: a private key is never stored or served.
package keys

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
	"github.com/selfagency/sovereign/internal/keys"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/me/keys* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds a keys Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// createReq is the body for creating a public key. KeyMaterial is the raw
// public key (SSH authorized_keys line or ASCII-armored PGP block); label is
// optional.
type createReq struct {
	Type        string `json:"type"`
	KeyMaterial string `json:"public_key"`
	Label       string `json:"label"`
}

// List returns the authenticated principal's public keys, optionally filtered
// by the ?type= query parameter ("ssh" | "pgp").
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	keyType := r.URL.Query().Get("type")
	if keyType != "" && keyType != "ssh" && keyType != "pgp" {
		problem.ValidationFailed([]problem.FieldError{{Field: "type", Code: "invalid", Detail: "type must be \"ssh\" or \"pgp\""}}).Write(w)
		return
	}
	rows, err := h.store.ListPublicKeys(r.Context(), u.TenantID, keyType)
	if err != nil {
		h.logger.Error("keys: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.PublicKey, 0, len(rows))
	for i := range rows {
		out = append(out, publicKeyDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// Get returns a single public key by ID, scoped to the authenticated tenant.
// A key that does not exist (including one owned by another tenant) yields 404.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	id, ok := keyIDFromPath(w, r)
	if !ok {
		return
	}
	k, err := h.store.GetPublicKey(r.Context(), u.TenantID, id)
	if err != nil {
		h.writeStoreErr(w, err, "get key")
		return
	}
	writeJSON(w, http.StatusOK, publicKeyDTO(k))
}

// Create validates and stores a new public key for the authenticated principal.
// The key material is parsed through internal/keys (SSH or PGP), which rejects
// private-key material fail-closed. Returns the created key with 201.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	parsed, err := parseKeyMaterial(req.Type, req.KeyMaterial)
	if err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "public_key", Code: "invalid", Detail: err.Error()}}).Write(w)
		return
	}
	k := &store.PublicKey{
		ID:          newKeyID(),
		TenantID:    u.TenantID,
		AccountID:   u.ID,
		KeyType:     req.Type,
		Label:       strings.TrimSpace(req.Label),
		Fingerprint: parsed.fingerprint,
		KeyMaterial: parsed.material,
		Algorithm:   parsed.algorithm,
		ExpiresAt:   parsed.expiresAt,
	}
	if err := h.store.CreatePublicKey(r.Context(), k); err != nil {
		if errors.Is(err, store.ErrDuplicateFingerprint) {
			problem.Conflict().Write(w)
			return
		}
		h.logger.Error("keys: create", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, publicKeyDTO(k))
}

// Delete removes a public key by ID, scoped to the authenticated tenant.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	id, ok := keyIDFromPath(w, r)
	if !ok {
		return
	}
	if err := h.store.DeletePublicKey(r.Context(), u.TenantID, u.ID, id); err != nil {
		h.writeStoreErr(w, err, "delete key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Revoke marks a public key revoked by ID, scoped to the authenticated tenant.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	id, ok := keyIDFromPath(w, r)
	if !ok {
		return
	}
	if err := h.store.RevokePublicKey(r.Context(), u.TenantID, u.ID, id); err != nil {
		h.writeStoreErr(w, err, "revoke key")
		return
	}
	k, err := h.store.GetPublicKey(r.Context(), u.TenantID, id)
	if err != nil {
		h.writeStoreErr(w, err, "reload key")
		return
	}
	writeJSON(w, http.StatusOK, publicKeyDTO(k))
}

// --- helpers ---

// parsedKey holds the canonical fields derived from validated key material.
type parsedKey struct {
	fingerprint string
	material    string
	algorithm   string
	expiresAt   *time.Time
}

// parseKeyMaterial routes SSH vs PGP material through internal/keys. It is
// fail-closed: private-key material is rejected before anything is stored.
func parseKeyMaterial(kind, raw string) (*parsedKey, error) {
	switch kind {
	case "ssh":
		k, err := keys.ParseSSHPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return &parsedKey{fingerprint: k.Fingerprint, material: k.Line, algorithm: k.Algorithm}, nil
	case "pgp":
		k, err := keys.ParsePGPPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return &parsedKey{fingerprint: k.Fingerprint, material: k.Armored, algorithm: k.Algorithm, expiresAt: k.ExpiresAt}, nil
	default:
		return nil, errors.New("type must be \"ssh\" or \"pgp\"")
	}
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
			h.logger.Error("keys: load user", "err", err)
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
	h.logger.Error("keys: "+op, "err", err)
	problem.Internal().Write(w)
}

// keyIDFromPath extracts the {id} segment from the request path. ServeMux
// populates PathValue when the route is registered with a {id} pattern; for
// direct handler invocation (tests) it falls back to the last path segment.
func keyIDFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
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

// newKeyID returns a new random hex key ID (16 bytes).
func newKeyID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("keys: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

// publicKeyDTO converts a stored key to the wire DTO.
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
