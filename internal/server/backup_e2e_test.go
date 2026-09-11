package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// TestBackupConfigE2E verifies the backup wiring end to end: an admin sets a
// backup config via the API, the scheduler starts from it, and a manual run
// writes a backup to the destination (T5 acceptance: "admin sets backup
// config, Status reflects it").
func TestBackupConfigE2E(t *testing.T) {
	ts := startTestServer(t, &Config{}, false)
	ctx := context.Background()

	// Seed an admin user (IsAdmin=true) and mint a token with the backup
	// scopes.
	must(t, ts.srv.store.CreateUser(ctx, &store.User{ID: "admin1", TenantID: "identity", Handle: "root", IsAdmin: true}))
	tok, err := auth.MintAccessToken(ts.srv.authStore.SigningKeyMaterial(), "admin1", []string{"admin:backup:write", "admin:backup:read"}, auth.AccessTokenTTL, "https://id."+ts.srv.cfg.Domain, "sovereign-api")
	must(t, err)

	// PUT a backup config (fs destination under the data dir).
	body := `{"schedule":"0 3 * * *","destination":"fs","prefix":"backups"}`
	req, err := http.NewRequest(http.MethodPut, ts.baseURL+"/api/v1/admin/backup/config", strings.NewReader(body))
	must(t, err)
	req.Host = "id.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := noRedirectClient().Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT backup config = %d, want 200", resp.StatusCode)
	}

	// GET the config back — it must reflect the saved values.
	req, err = http.NewRequest(http.MethodGet, ts.baseURL+"/api/v1/admin/backup/config", http.NoBody)
	must(t, err)
	req.Host = "id.example.com"
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err = noRedirectClient().Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET backup config = %d, want 200", resp.StatusCode)
	}
	var cfg struct {
		Schedule    string `json:"schedule"`
		Destination string `json:"destination"`
		Prefix      string `json:"prefix"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if cfg.Schedule != "0 3 * * *" || cfg.Destination != "fs" || cfg.Prefix != "backups" {
		t.Fatalf("config = %+v, want schedule=0 3 * * * destination=fs prefix=backups", cfg)
	}

	// Trigger a manual run — the scheduler must write a backup to the fs
	// destination (the data dir's blobs backend).
	req, err = http.NewRequest(http.MethodPost, ts.baseURL+"/api/v1/admin/backup/runs", http.NoBody)
	must(t, err)
	req.Host = "id.example.com"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Idempotency-Key", "e2e-backup-run")
	resp, err = noRedirectClient().Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("trigger run = %d, want 201", resp.StatusCode)
	}
	var run struct {
		Status string  `json:"status"`
		Error  *string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if run.Status != "succeeded" {
		errMsg := ""
		if run.Error != nil {
			errMsg = *run.Error
		}
		t.Fatalf("run status = %q, want succeeded (error: %s)", run.Status, errMsg)
	}
}
