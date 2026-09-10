// Package moderation implements the /api/v1/admin/moderation* instance-admin
// endpoints for managing content takedowns: list, create, get by id, and
// delete (lift). Admin is INSTANCE-scoped: takedowns are not filtered by the
// caller's tenant. Authorization is enforced by the scope middleware
// (admin:moderation:* + IsAdmin); the handlers additionally require an admin
// principal as defense-in-depth so a non-admin principal can never reach the
// store. Every state-changing action writes an audit entry whose actor is the
// authenticated admin principal (A8), never a static value.
package moderation

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/admin/moderation* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds an admin moderation Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// createReq is the body for creating a takedown.
type createReq struct {
	Resource string `json:"resource"`
	Reason   string `json:"reason"`
}

// List returns a page of all takedowns, newest first, with the total count.
// limit and offset are read from the query string (defaults: limit 100,
// offset 0).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	limit, offset := 100, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem.ValidationFailed([]problem.FieldError{{Field: "limit", Code: "invalid", Detail: "limit must be a non-negative integer"}}).Write(w)
			return
		}
		limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem.ValidationFailed([]problem.FieldError{{Field: "offset", Code: "invalid", Detail: "offset must be a non-negative integer"}}).Write(w)
			return
		}
		offset = n
	}
	rows, total, err := h.store.ListTakedowns(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("moderation: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.Takedown, 0, len(rows))
	for i := range rows {
		out = append(out, takedownDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.Takedown]{Data: out, Offset: offset, Limit: limit, Total: total})
}

// Create validates and stores a new takedown. Returns the created takedown
// with 201. It also writes an audit entry with the authenticated admin
// principal as the actor (A8).
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	req.Resource = strings.TrimSpace(req.Resource)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Resource == "" || req.Reason == "" {
		problem.ValidationFailed([]problem.FieldError{{Field: "body", Code: "invalid", Detail: "resource and reason are required"}}).Write(w)
		return
	}
	now := time.Now().UTC()
	t := &store.Takedown{
		ID:        newTakedownID(),
		Resource:  req.Resource,
		Reason:    req.Reason,
		ActedBy:   p.UserID,
		CreatedAt: now,
	}
	if err := h.store.CreateTakedown(r.Context(), t); err != nil {
		h.logger.Error("moderation: create", "err", err)
		problem.Internal().Write(w)
		return
	}
	if err := h.audit(r, p, "takedown", t.Resource, t.Reason); err != nil {
		h.logger.Error("moderation: create audit", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, takedownDTO(t))
}

// GetByID returns a single takedown by its ID, or 404 when missing.
func (h *Handler) GetByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	t, err := h.store.TakedownByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "get takedown by id")
		return
	}
	writeJSON(w, http.StatusOK, takedownDTO(t))
}

// Delete removes a takedown by ID (lifts the takedown). Returns 204 on
// success, 404 when the takedown does not exist. It also writes an audit entry
// with the authenticated admin principal as the actor (A8).
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	t, err := h.store.TakedownByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "get takedown for delete")
		return
	}
	if err := h.store.DeleteTakedown(r.Context(), id); err != nil {
		h.writeStoreErr(w, err, "delete takedown")
		return
	}
	if err := h.audit(r, p, "takedown-lift", t.Resource, t.Reason); err != nil {
		h.logger.Error("moderation: delete audit", "err", err)
		problem.Internal().Write(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// audit writes an audit entry for a moderation action, using the authenticated
// admin principal as the actor (A8). The tenant is taken from the request
// context (set by the tenant middleware), never from client input.
func (h *Handler) audit(r *http.Request, p *middleware.Principal, action, target, detail string) error {
	return h.store.AppendAudit(r.Context(), &store.AuditEntry{
		ID:        newTakedownID(),
		TenantID:  p.TenantID,
		Actor:     p.UserID,
		Action:    action,
		Target:    target,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	})
}

// admin returns the authenticated principal, requiring it to be an instance
// admin. It writes 401 when unauthenticated and 403 when the principal is not
// an admin. The scope middleware normally enforces this; the check here is
// defense-in-depth so a non-admin principal can never reach the store.
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

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("moderation: "+op, "err", err)
	problem.Internal().Write(w)
}

// pathValue extracts the named path segment, falling back to the last path
// segment for direct handler invocation in tests.
func pathValue(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if v == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		v = seg[len(seg)-1]
	}
	if v == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return v, true
}

// newTakedownID returns a new random hex ID (16 bytes).
func newTakedownID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("moderation: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

// takedownDTO converts a stored takedown to the wire DTO.
func takedownDTO(t *store.Takedown) dto.Takedown {
	return dto.Takedown{
		ID:        t.ID,
		Resource:  t.Resource,
		Reason:    t.Reason,
		ActedBy:   t.ActedBy,
		CreatedAt: t.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
