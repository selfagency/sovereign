// Package meta implements the /meta, /health, /ready, and /openapi.json
// control-plane endpoints of the versioned REST API. These routes are
// anonymous (no authn/scope) and report process-level facts: wired features,
// build version, liveness, readiness, and the embedded OpenAPI document.
package meta

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/openapi"
)

// VersionInfo carries the build stamp for /meta/version. Version is the
// required field; Commit and GoVersion are optional (empty when the build was
// not stamped via ldflags).
type VersionInfo struct {
	Version   string
	Commit    string
	GoVersion string
}

// Handler serves the anonymous meta/health/ready/openapi routes.
type Handler struct {
	capabilities dto.Capabilities
	version      VersionInfo
	ping         func(ctx context.Context) error
	spec         []byte
}

// Option configures a Handler. The zero Handler is usable but reports no
// capabilities and a failing readiness, so production wiring should provide
// the real dependencies via these options.
type Option func(*Handler)

// WithCapabilities sets the wired-feature report served at /meta/capabilities.
func WithCapabilities(c dto.Capabilities) Option {
	return func(h *Handler) { h.capabilities = c }
}

// WithVersion stamps the /meta/version build info.
func WithVersion(v VersionInfo) Option {
	return func(h *Handler) { h.version = v }
}

// WithPing sets the readiness probe. When nil, /ready fails closed with 503.
func WithPing(p func(ctx context.Context) error) Option {
	return func(h *Handler) { h.ping = p }
}

// New builds a Handler with the given options.
func New(opts ...Option) *Handler {
	h := &Handler{}
	for _, o := range opts {
		o(h)
	}
	if h.spec == nil {
		// Load once at construction; production wiring constructs a single
		// Handler so this runs a single time per process.
		if b, err := openapi.SpecJSON(); err == nil {
			h.spec = b
		}
	}
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Capabilities serves the machine-readable list of wired features.
func (h *Handler) Capabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.capabilities)
}

// Version serves the build version. GoVersion is filled from runtime at
// request time when not explicitly stamped, so the report stays accurate.
func (h *Handler) Version(w http.ResponseWriter, _ *http.Request) {
	v := h.version
	if v.GoVersion == "" {
		v.GoVersion = runtime.Version()
	}
	writeJSON(w, http.StatusOK, dto.Version{
		Version:   v.Version,
		Commit:    v.Commit,
		GoVersion: v.GoVersion,
	})
}

// Health serves the liveness probe. Liveness means the process is up, so it
// performs no dependency checks.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, dto.Health{Status: "ok"})
}

// Ready serves the readiness probe. It pings the store and returns 503 when
// the store is unreachable. It fails closed (503) when no ping is wired.
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	if h.ping == nil || h.ping(r.Context()) != nil {
		problem.ServiceUnavailable().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, dto.Health{Status: "ok"})
}

// OpenAPI serves the embedded OpenAPI document as JSON.
func (h *Handler) OpenAPI(w http.ResponseWriter, _ *http.Request) {
	if h.spec == nil {
		problem.Internal().Write(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.spec)
}
