// Package tenants implements the /api/v1/admin/tenants* instance-admin
// endpoints for managing tenants: list, get by id, get by DID, create, and
// delete. Admin is INSTANCE-scoped: these handlers operate on every tenant in
// the store, not just the caller's own. Authorization is enforced by the scope
// middleware (admin:tenants:* scope + IsAdmin); the handlers additionally
// require an admin principal as defense-in-depth so a non-admin principal can
// never reach the store.
package tenants

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/admin/tenants* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds an admin tenants Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// createReq is the body for creating a tenant. ID is optional; when omitted a
// random ID is generated. Handle is the tenant's host/handle; did is the
// tenant's DID.
type createReq struct {
	ID        string `json:"id"`
	Handle    string `json:"handle"`
	DIDMethod string `json:"did_method"`
	DID       string `json:"did"`
}

// List returns a page of all tenants, ordered by handle, with the total count.
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
	rows, total, err := h.store.ListTenantsPage(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("tenants: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.Tenant, 0, len(rows))
	for i := range rows {
		out = append(out, tenantDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.Tenant]{Data: out, Offset: offset, Limit: limit, Total: total})
}

// GetByID returns a single tenant by its ID, or 404 when missing.
func (h *Handler) GetByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	t, err := h.store.GetTenantByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "get tenant by id")
		return
	}
	writeJSON(w, http.StatusOK, tenantDTO(t))
}

// GetByDID returns a single tenant by its DID, or 404 when missing.
func (h *Handler) GetByDID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	did, ok := pathValue(w, r, "did")
	if !ok {
		return
	}
	t, err := h.store.GetTenantByDID(r.Context(), did)
	if err != nil {
		h.writeStoreErr(w, err, "get tenant by did")
		return
	}
	writeJSON(w, http.StatusOK, tenantDTO(t))
}

// Create validates and stores a new tenant. Returns the created tenant with
// 201, or 409 when the handle already exists.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	req.Handle = strings.TrimSpace(req.Handle)
	req.DID = strings.TrimSpace(req.DID)
	if err := validateCreate(&req); err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "body", Code: "invalid", Detail: err.Error()}}).Write(w)
		return
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		id = newTenantID()
	}
	t := &store.Tenant{
		ID:        id,
		Handle:    req.Handle,
		DIDMethod: req.DIDMethod,
		DID:       req.DID,
	}
	if err := h.store.CreateTenant(r.Context(), t); err != nil {
		if errors.Is(err, store.ErrDuplicateTenant) {
			problem.Conflict().Write(w)
			return
		}
		h.logger.Error("tenants: create", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, tenantDTO(t))
}

// Delete removes a tenant by handle. This is a destructive admin action: the
// store cascades the delete to the tenant's users and accounts (FK ON DELETE
// CASCADE). Returns 204 on success, 404 when the tenant does not exist.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	handle, ok := pathValue(w, r, "handle")
	if !ok {
		return
	}
	if err := h.store.DeleteTenant(r.Context(), handle); err != nil {
		h.writeStoreErr(w, err, "delete tenant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

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
	h.logger.Error("tenants: "+op, "err", err)
	problem.Internal().Write(w)
}

// validateCreate validates the create-tenant request body.
func validateCreate(req *createReq) error {
	if req.Handle == "" {
		return errors.New("handle is required")
	}
	if req.DID == "" {
		return errors.New("did is required")
	}
	if !validDID(req.DID) {
		return errors.New("did must be a valid DID (did:<method>:<id>)")
	}
	return nil
}

// validDID reports whether s is a well-formed DID: did:<method>:<id>.
func validDID(s string) bool {
	parts := strings.Split(s, ":")
	return len(parts) >= 3 && parts[0] == "did" && parts[1] != "" && parts[2] != ""
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

// newTenantID returns a new random hex tenant ID (16 bytes).
func newTenantID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("tenants: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

// tenantDTO converts a stored tenant to the wire DTO.
func tenantDTO(t *store.Tenant) dto.Tenant {
	return dto.Tenant{
		ID:        t.ID,
		Handle:    t.Handle,
		DID:       t.DID,
		CreatedAt: t.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
