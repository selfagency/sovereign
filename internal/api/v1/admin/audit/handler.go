// Package audit implements the /api/v1/admin/audit instance-admin endpoint
// that returns the persistent audit log across all tenants. Admin is
// INSTANCE-scoped: the log is not filtered by the caller's tenant. The actor
// field (A8) is the real authenticated principal that performed each action,
// never a static value. Authorization is enforced by the scope middleware
// (admin:audit + IsAdmin); the handler additionally requires an admin
// principal as defense-in-depth.
package audit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/admin/audit endpoint.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds an admin audit Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// List returns a page of audit entries across all tenants, newest first, with
// the total count. limit and offset are read from the query string (defaults:
// limit 100, offset 0). Each entry carries the real actor (A8).
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
	rows, total, err := h.store.ListAuditAllPage(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("audit: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.AuditEntry, 0, len(rows))
	for i := range rows {
		out = append(out, auditDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.AuditEntry]{Data: out, Offset: offset, Limit: limit, Total: total})
}

// --- helpers ---

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

// auditDTO converts a stored audit entry to the wire DTO. The actor is the
// real principal who performed the action (A8).
func auditDTO(e *store.AuditEntry) dto.AuditEntry {
	return dto.AuditEntry{
		ID:        e.ID,
		Actor:     e.Actor,
		Action:    e.Action,
		Resource:  e.Target,
		Detail:    e.Detail,
		CreatedAt: e.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
