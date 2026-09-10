package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestOIDCDiscovery verifies the OIDC provider is reachable on the identity
// host and serves discovery metadata with the correct issuer.
func TestOIDCDiscovery(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)

	// Discovery on the identity host.
	status, body := ts.get(t, "/.well-known/openid-configuration", "id.example.com")
	if status != 200 {
		t.Fatalf("discovery status = %d, want 200 (body %q)", status, body)
	}
	var disc map[string]any
	if err := json.Unmarshal([]byte(body), &disc); err != nil {
		t.Fatalf("discovery not JSON: %v", err)
	}
	if iss, _ := disc["issuer"].(string); iss != "https://id.example.com" {
		t.Fatalf("issuer = %q, want https://id.example.com", iss)
	}
	// The provider must advertise the standard endpoints.
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"} {
		if _, ok := disc[k]; !ok {
			t.Fatalf("discovery missing %q", k)
		}
	}
}

// TestOIDCJWKS verifies the JWKS endpoint serves the signing key.
func TestOIDCJWKS(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)

	status, body := ts.get(t, "/keys", "id.example.com")
	if status != 200 {
		t.Fatalf("jwks status = %d, want 200 (body %q)", status, body)
	}
	if !strings.Contains(body, "RSA") && !strings.Contains(body, "keys") {
		t.Fatalf("jwks body = %q", body)
	}
}

// TestOIDCNotOnTenantHost verifies the OIDC provider is NOT served on a
// tenant host (only the identity host serves it).
func TestOIDCNotOnTenantHost(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	// A tenant host must not serve OIDC discovery (it serves the protocol
	// mux, which 404s unknown paths).
	status, _ := ts.get(t, "/.well-known/openid-configuration", "alice.example.com")
	if status == 200 {
		t.Fatal("OIDC discovery served on tenant host")
	}
}

// TestWebAuthnNotOnTenantHost verifies WebAuthn endpoints are not served on
// tenant hosts (the legacy /webauthn/* routes are removed; the passkey flow
// lives on /api/v1/auth/webauthn/*).
func TestWebAuthnNotOnTenantHost(t *testing.T) {
	ts := startTestServer(t, &Config{}, true)

	status, _ := ts.get(t, "/webauthn/register/begin?handle=nobody", "alice.example.com")
	if status == 200 {
		t.Fatal("WebAuthn served on tenant host")
	}
}

// TestAdminModerationRequiresAuth verifies the admin moderation route rejects
// unauthenticated requests.
func TestAdminModerationRequiresAuth(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)

	status, _ := ts.get(t, "/admin/moderation/takedown", "id.example.com")
	if status != http.StatusUnauthorized {
		t.Fatalf("admin moderation no-token status = %d, want 401", status)
	}
}
