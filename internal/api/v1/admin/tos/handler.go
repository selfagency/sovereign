// Package tos implements the /api/v1/admin/tos instance-admin endpoints for
// managing the published Terms of Service: GET returns the latest document,
// PUT publishes a new version (scoped to admin:system:write, matching the
// instance-config surface). Admin is INSTANCE-scoped. Authorization is
// enforced by the scope middleware (admin:system + IsAdmin); the handler
// additionally requires an admin principal as defense-in-depth.
package tos

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
)

// Handler serves the /api/v1/admin/tos endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds an admin ToS Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// putReq is the body for publishing a ToS version.
type putReq struct {
	Version string `json:"version"`
	Content string `json:"content"`
}

// Get returns the most recently published ToS document, or 404 when none has
// been published yet.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	d, err := h.store.GetLatestToSDocument(r.Context())
	if err != nil {
		h.writeStoreErr(w, err, "get tos")
		return
	}
	writeJSON(w, http.StatusOK, tosDTO(d))
}

// Put publishes a new ToS version, recording the publishing admin as the
// author. Returns 201 with the stored document.
func (h *Handler) Put(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	var req putReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	req.Version = strings.TrimSpace(req.Version)
	req.Content = strings.TrimSpace(req.Content)
	if req.Version == "" || req.Content == "" {
		problem.ValidationFailed([]problem.FieldError{{Field: "body", Code: "invalid", Detail: "version and content are required"}}).Write(w)
		return
	}
	d := &store.ToSDocument{
		ID:          newTosID(),
		Version:     req.Version,
		Content:     req.Content,
		PublishedAt: time.Now().UTC(),
		PublishedBy: p.UserID,
	}
	if err := h.store.UpsertToSDocument(r.Context(), d); err != nil {
		h.logger.Error("tos: put", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, tosDTO(d))
}

// --- helpers ---

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("tos: "+op, "err", err)
	problem.Internal().Write(w)
}

// admin returns the authenticated principal, requiring it to be an instance
// admin. It writes 401 when unauthenticated and 403 when the principal is not
// an admin. Defense-in-depth beyond the scope middleware.
func (h *Handler) admin(w http.ResponseWriter, r *http.Request) (*middleware.Principal, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return nil, false
	}
	if !p.IsAdmin {
		problem.Forbidden().Write(w)
		return nil, false
	}
	return p, true
}

func newTosID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("tos: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

func tosDTO(d *store.ToSDocument) dto.ToSDocument {
	return dto.ToSDocument{
		ID:          d.ID,
		Version:     d.Version,
		Content:     d.Content,
		PublishedAt: d.PublishedAt,
		PublishedBy: d.PublishedBy,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
