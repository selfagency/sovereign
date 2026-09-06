// Package deletions implements the /api/v1/admin/deletion-requests* instance
// -admin endpoints for managing account-deletion requests: list, approve
// (cascades the account deletion), and reject. Admin is INSTANCE-scoped. The
// approving/rejecting admin principal is recorded as the actor (A8) on the
// request and in the audit log. Authorization is enforced by the scope
// middleware (admin:users + IsAdmin); the handlers additionally require an
// admin principal as defense-in-depth.
package deletions

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

// Handler serves the /api/v1/admin/deletion-requests* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds an admin deletions Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// List returns a page of deletion requests (newest first) with the total
// count. limit and offset are read from the query string (defaults: limit
// 100, offset 0).
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
	rows, total, err := h.store.ListPendingDeletions(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("deletions: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.PendingDeletion, 0, len(rows))
	for i := range rows {
		out = append(out, pendingDeletionDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.PendingDeletion]{Data: out, Offset: offset, Limit: limit, Total: total})
}

// Approve approves a deletion request and cascade-deletes the user. Returns
// 200 with the updated request. It is idempotent: approving an already
// processed request is a no-op returning the current state.
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	if err := h.store.ApprovePendingDeletion(r.Context(), id, p.UserID); err != nil {
		h.writeStoreErr(w, err, "approve deletion request")
		return
	}
	req, err := h.store.PendingDeletionByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "approve deletion request")
		return
	}
	if err := h.audit(r, p, "deletion.approve", id, "user "+req.UserID); err != nil {
		h.logger.Error("deletions: approve audit", "err", err)
	}
	writeJSON(w, http.StatusOK, pendingDeletionDTO(req))
}

// Reject rejects a deletion request, leaving the account intact. Returns 200
// with the updated request. It is idempotent: rejecting an already processed
// request is a no-op returning the current state.
func (h *Handler) Reject(w http.ResponseWriter, r *http.Request) {
	p, ok := h.admin(w, r)
	if !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	if err := h.store.RejectPendingDeletion(r.Context(), id, p.UserID); err != nil {
		h.writeStoreErr(w, err, "reject deletion request")
		return
	}
	req, err := h.store.PendingDeletionByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "reject deletion request")
		return
	}
	if err := h.audit(r, p, "deletion.reject", id, "user "+req.UserID); err != nil {
		h.logger.Error("deletions: reject audit", "err", err)
	}
	writeJSON(w, http.StatusOK, pendingDeletionDTO(req))
}

// --- helpers ---

// audit writes an audit entry for an admin deletion action, using the
// authenticated admin principal as the actor (A8).
func (h *Handler) audit(r *http.Request, p *middleware.Principal, action, target, detail string) error {
	return h.store.AppendAudit(r.Context(), &store.AuditEntry{
		ID:        newDeletionID(),
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

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("deletions: "+op, "err", err)
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

// newDeletionID returns a new random hex ID (16 bytes).
func newDeletionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("deletions: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

// pendingDeletionDTO converts a stored deletion request to the wire DTO.
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
