// Package api provides the versioned JSON REST API surface (/api/v1).
//
// The route table in this file is the single source of truth for which
// endpoints exist, what scope each requires, and its per-route timeout.
// The OpenAPI drift test (openapi_drift_test.go) asserts this table stays
// in parity with openapi/sovereign.v1.yaml in both directions.
package api

import (
	"net/http"
	"time"
)

// Route describes one HTTP endpoint on the /api/v1 surface.
type Route struct {
	Method  string        // "GET", "POST", ...
	Path    string        // "/api/v1/meta/capabilities"
	Scope   string        // required scope, or "" for anonymous
	Timeout time.Duration // per-route timeout
	Handler http.HandlerFunc
}

// Routes returns the current route set. Phase 1 endpoints only; later
// phases (T1.3 and endpoint tasks) expand this table.
func Routes() []Route {
	return []Route{
		// Meta / health / ready (anonymous).
		{Method: http.MethodGet, Path: "/api/v1/meta/capabilities", Scope: "", Timeout: 5 * time.Second},
		{Method: http.MethodGet, Path: "/api/v1/meta/version", Scope: "", Timeout: 5 * time.Second},
		{Method: http.MethodGet, Path: "/api/v1/health", Scope: "", Timeout: 5 * time.Second},
		{Method: http.MethodGet, Path: "/api/v1/ready", Scope: "", Timeout: 5 * time.Second},
		{Method: http.MethodGet, Path: "/api/v1/openapi.json", Scope: "", Timeout: 5 * time.Second},

		// Auth & session.
		{Method: http.MethodPost, Path: "/api/v1/auth/invite/redeem", Scope: "", Timeout: 10 * time.Second},
		{Method: http.MethodGet, Path: "/api/v1/auth/session", Scope: "", Timeout: 5 * time.Second},
		{Method: http.MethodDelete, Path: "/api/v1/auth/session", Scope: "", Timeout: 5 * time.Second},
		{Method: http.MethodPost, Path: "/api/v1/auth/session/refresh", Scope: "", Timeout: 5 * time.Second},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/begin", Scope: "", Timeout: 10 * time.Second},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/finish", Scope: "", Timeout: 10 * time.Second},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/begin", Scope: "", Timeout: 10 * time.Second},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/finish", Scope: "", Timeout: 10 * time.Second},
	}
}
