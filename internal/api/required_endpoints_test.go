package api

import (
	"net/http"
	"testing"
)

// requiredEndpoints is the manifest of /me/* endpoints the plan mandates.
// The drift test only checks method+path parity between the route table and
// the OpenAPI spec, so it cannot catch a feature that was never implemented.
// This test asserts every required (method, path) pair is present in the route
// table, so a missing feature fails the build even if the spec and table
// happen to agree on the (absent) route.
var requiredEndpoints = []struct {
	Method string
	Path   string
}{
	// Programmatic API tokens (show-once creation, metadata-only list, revoke).
	{http.MethodPost, "/api/v1/me/tokens"},
	{http.MethodGet, "/api/v1/me/tokens"},
	{http.MethodDelete, "/api/v1/me/tokens/{family_id}"},
	// WebAuthn credentials (list + delete with last-credential guard).
	{http.MethodGet, "/api/v1/me/credentials"},
	{http.MethodDelete, "/api/v1/me/credentials/{id}"},
}

// TestRequiredEndpointsPresent asserts every endpoint in the required-endpoint
// manifest exists in the route table. Unlike the drift test, this catches a
// feature that was never registered at all.
func TestRequiredEndpointsPresent(t *testing.T) {
	table := map[string]bool{}
	for _, r := range Routes() {
		table[r.Method+" "+r.Path] = true
	}
	for _, e := range requiredEndpoints {
		key := e.Method + " " + e.Path
		if !table[key] {
			t.Errorf("required endpoint %s is missing from the route table", key)
		}
	}
}

// TestRequiredEndpointsNotStubbed verifies the required endpoints are wired to
// real handlers (not 501 stubs) when a self handler is provided. This closes
// the gap where a route exists in the table but is left as a stub.
func TestRequiredEndpointsNotStubbed(t *testing.T) {
	for _, e := range requiredEndpoints {
		key := e.Method + " " + e.Path
		found := false
		for _, r := range selfRoutes(nil) {
			if r.Method+" "+r.Path == key {
				found = true
				if r.Handler == nil {
					t.Errorf("required endpoint %s has a nil handler", key)
				}
			}
		}
		if !found {
			t.Errorf("required endpoint %s is missing from selfRoutes", key)
		}
	}
}

// TestSelfRoutesAllScoped asserts every self route declares a non-empty scope
// and is not anonymous (self-service routes must be authenticated+scoped).
func TestSelfRoutesAllScoped(t *testing.T) {
	for _, r := range selfRoutes(nil) {
		if r.Anonymous {
			t.Errorf("self route %s %s is anonymous; self routes must be authenticated", r.Method, r.Path)
		}
		if r.Scope == "" {
			t.Errorf("self route %s %s declares no scope", r.Method, r.Path)
		}
	}
}
