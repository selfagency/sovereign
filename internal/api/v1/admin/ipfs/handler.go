// Package ipfs implements the /api/v1/admin/ipfs/pins* instance-admin
// endpoints for the IPFS pinning broker: list pinned CIDs, add a pin, and get
// a pin's status by CID. Admin is INSTANCE-scoped. The CID is validated with a
// non-panicking parse (invalid input returns 400, never a panic); the store
// persists the raw string as given. When an ipfspin.Backend is configured, the
// add-pin handler also calls the backend to pin the CID (a no-op backend is
// accepted). Authorization is enforced by the scope middleware (admin:ipfs +
// IsAdmin); the handler additionally requires an admin principal as
// defense-in-depth.
package ipfs

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ipfs/go-cid"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/protocols/ipfspin"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/admin/ipfs/pins* endpoints.
type Handler struct {
	store   *store.Store
	backend ipfspin.Backend // optional; nil disables the backend call
	logger  *slog.Logger
}

// New builds an admin IPFS Handler. backend may be nil.
func New(st *store.Store, backend ipfspin.Backend, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, backend: backend, logger: logger}
}

// addReq is the body for adding a pin.
type addReq struct {
	CID string `json:"cid"`
}

// List returns every pinned CID, oldest first.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	rows, err := h.store.ListIPFSPins(r.Context())
	if err != nil {
		h.logger.Error("ipfs: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.IPFSPin, 0, len(rows))
	for i := range rows {
		out = append(out, ipfsPinDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// Add validates and records a new pin. An invalid CID returns 400; a pin with
// no CID returns 400. When a backend is configured it pins the CID first.
func (h *Handler) Add(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	var req addReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CID == "" {
		problem.InvalidRequest("missing or invalid body: cid is required").Write(w)
		return
	}
	parsed, err := cid.Decode(req.CID)
	if err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "cid", Code: "invalid", Detail: "cid must be a valid IPFS content identifier"}}).Write(w)
		return
	}
	if h.backend != nil {
		if err := h.backend.Pin(r.Context(), parsed); err != nil {
			h.logger.Error("ipfs: backend pin", "cid", req.CID, "err", err)
			problem.Internal().Write(w)
			return
		}
	}
	if err := h.store.AddIPFSPin(r.Context(), req.CID, "pinned"); err != nil {
		h.logger.Error("ipfs: store pin", "cid", req.CID, "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, dto.IPFSPin{CID: req.CID, Status: "pinned"})
}

// GetByCID returns a pin's status by CID, or 404 when not pinned.
func (h *Handler) GetByCID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	raw, ok := pathValue(w, r, "cid")
	if !ok {
		return
	}
	// Validate without panicking; the store persists the raw string as given.
	if _, err := cid.Decode(raw); err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "cid", Code: "invalid", Detail: "cid must be a valid IPFS content identifier"}}).Write(w)
		return
	}
	p, err := h.store.GetIPFSPin(r.Context(), raw)
	if err != nil {
		h.writeStoreErr(w, err, "get ipfs pin by cid")
		return
	}
	writeJSON(w, http.StatusOK, ipfsPinDTO(p))
}

// --- helpers ---

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if err == store.ErrNotFound {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("ipfs: "+op, "err", err)
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

// pathValue extracts the named path segment, falling back to the last path
// segment for direct handler invocation in tests.
func pathValue(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if v == "" {
		seg := splitPath(r.URL.Path)
		v = seg[len(seg)-1]
	}
	if v == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return v, true
}

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func ipfsPinDTO(p *store.IPFSPin) dto.IPFSPin {
	return dto.IPFSPin{CID: p.CID, Status: p.Status, CreatedAt: p.CreatedAt}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
