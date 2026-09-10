// Package system implements the /api/v1/admin/system/info instance-admin
// endpoint that returns a summary of the server configuration with secrets
// redacted. Admin is INSTANCE-scoped. Authorization is enforced by the scope
// middleware (admin:system + IsAdmin); the handler additionally requires an
// admin principal as defense-in-depth.
package system

import (
	"encoding/json"
	"net/http"

	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
)

// Info is the config summary returned by /admin/system/info. Secret fields
// (SMTP password, S3 keys) are deliberately absent or redacted.
type Info struct {
	Domain            string   `json:"domain"`
	Audience          string   `json:"audience"`
	DataDir           string   `json:"data_dir"`
	OpenRegistrations bool     `json:"open_registrations"`
	StorageBackend    string   `json:"storage_backend"`
	IPFSEnabled       bool     `json:"ipfs_enabled"`
	SMTPEnabled       bool     `json:"smtp_enabled"`
	SMTPHost          string   `json:"smtp_host,omitempty"`
	SMTPFrom          string   `json:"smtp_from,omitempty"`
	APICORSOrigins    []string `json:"api_cors_origins,omitempty"`
}

// Handler serves the /api/v1/admin/system/info endpoint.
type Handler struct {
	info *Info
}

// New builds an admin system Handler. info is the config summary to report
// (built by the server from its config, with secrets redacted).
func New(info *Info) *Handler {
	return &Handler{info: info}
}

// Info returns the config summary with secrets redacted.
func (h *Handler) Info(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.info)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
