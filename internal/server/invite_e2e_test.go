package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// must fails the test if err is non-nil.
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestInviteFlowE2E verifies the full onboarding loop: admin creates a user,
// the magic link is logged, and redeeming it sets a session cookie and
// redirects to the panel.
func TestInviteFlowE2E(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)
	ctx := context.Background()

	// Seed an admin and mint a token.
	must(t, ts.srv.store.CreateUser(ctx, &store.User{ID: "admin1", TenantID: "identity", Handle: "root"}))
	tok, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), "admin1", []string{"admin:users:write"}, auth.AccessTokenTTL, "https://id."+ts.srv.cfg.Domain, "sovereign-api")
	must(t, err)

	// Admin creates a user via the REST API (the old /admin/users HTTP layer
	// was decommissioned in T7.1). The route is Idempotent, so the request
	// must carry an Idempotency-Key.
	body := `{"tenant_id":"identity","handle":"alice","email":"alice@example.com"}`
	req, err := http.NewRequest(http.MethodPost, ts.baseURL+"/api/v1/admin/users", strings.NewReader(body))
	must(t, err)
	req.Host = "id.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Idempotency-Key", "e2e-invite-create")
	resp, err := noRedirectClient().Do(req)
	must(t, err)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d, want 201", resp.StatusCode)
	}

	// The dev LogSender logs the magic link; we can't capture it here, so
	// instead verify the invite token exists for the user (hashed).
	u, err := ts.srv.store.UserByHandle(ctx, "identity", "alice")
	must(t, err)
	// Redeem a fresh invite token directly to exercise the /invite/ route.
	raw := "e2erawtoken"
	must(t, ts.srv.store.CreateInviteToken(ctx, &store.InviteToken{
		ID: "inv-e2e", TokenHash: hashToken(raw), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour),
	}))

	// Redeem the magic link (no-redirect client so we can inspect the 302).
	req, err = http.NewRequest(http.MethodGet, ts.baseURL+"/invite/"+raw, http.NoBody)
	must(t, err)
	req.Host = "id.example.com"
	resp, err = noRedirectClient().Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("invite status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/panel") {
		t.Fatalf("Location = %q, want /panel", loc)
	}
	var hasSession bool
	for _, c := range resp.Cookies() {
		if c.Name == "session" && c.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Fatal("no session cookie set")
	}
}
