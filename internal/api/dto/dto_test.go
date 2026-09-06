package dto

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// mustTime parses a fixed RFC 3339 timestamp; panics on error so tests fail
// loudly on a malformed fixture.
func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad fixture time %q: %v", s, err)
	}
	return ts
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }

func golden(t *testing.T, name string, v any, want string) {
	t.Helper()
	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	if string(got) != want {
		t.Errorf("%s:\n got %s\nwant %s", name, got, want)
	}
}

func TestUserGolden(t *testing.T) {
	golden(t, "User", User{
		ID:          "user_1",
		TenantID:    "tenant_1",
		Email:       "ada@example.com",
		DisplayName: "Ada",
		IsAdmin:     true,
		TOSAccepted: true,
		CreatedAt:   mustTime(t, "2026-01-02T03:04:05Z"),
		UpdatedAt:   mustTime(t, "2026-02-03T04:05:06Z"),
	}, `{"id":"user_1","tenant_id":"tenant_1","email":"ada@example.com","display_name":"Ada","is_admin":true,"tos_accepted":true,"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-02-03T04:05:06Z"}`)
}

func TestTenantGolden(t *testing.T) {
	golden(t, "Tenant", Tenant{
		ID:        "tenant_1",
		Handle:    "ada",
		DID:       "did:key:z6Mk",
		CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"id":"tenant_1","handle":"ada","did":"did:key:z6Mk","created_at":"2026-01-02T03:04:05Z"}`)
}

func TestSessionGolden(t *testing.T) {
	active := Session{
		ID:            "sess_1",
		UserID:        "user_1",
		CreatedAt:     mustTime(t, "2026-01-02T03:04:05Z"),
		LastSeenAt:    ptr(mustTime(t, "2026-01-02T03:04:06Z")),
		ExpiresAt:     mustTime(t, "2026-01-03T03:04:05Z"),
		RevokedAt:     nil,
		UserAgentHash: "uahash",
		IPHash:        "iphash",
	}
	golden(t, "Session active", active, `{"id":"sess_1","user_id":"user_1","created_at":"2026-01-02T03:04:05Z","last_seen_at":"2026-01-02T03:04:06Z","expires_at":"2026-01-03T03:04:05Z","revoked_at":null,"user_agent_hash":"uahash","ip_hash":"iphash"}`)

	revoked := active
	revoked.RevokedAt = ptr(mustTime(t, "2026-01-02T04:00:00Z"))
	golden(t, "Session revoked", revoked, `{"id":"sess_1","user_id":"user_1","created_at":"2026-01-02T03:04:05Z","last_seen_at":"2026-01-02T03:04:06Z","expires_at":"2026-01-03T03:04:05Z","revoked_at":"2026-01-02T04:00:00Z","user_agent_hash":"uahash","ip_hash":"iphash"}`)
}

func TestPublicKeyGolden(t *testing.T) {
	key := PublicKey{
		ID:          "key_1",
		UserID:      "user_1",
		Type:        "ssh",
		Fingerprint: "SHA256:abc",
		PublicKey:   "ssh-ed25519 AAAAC3",
		CreatedAt:   mustTime(t, "2026-01-02T03:04:05Z"),
		RevokedAt:   nil,
	}
	golden(t, "PublicKey active", key, `{"id":"key_1","user_id":"user_1","type":"ssh","fingerprint":"SHA256:abc","public_key":"ssh-ed25519 AAAAC3","created_at":"2026-01-02T03:04:05Z","revoked_at":null}`)

	revoked := key
	revoked.RevokedAt = ptr(mustTime(t, "2026-01-05T00:00:00Z"))
	golden(t, "PublicKey revoked", revoked, `{"id":"key_1","user_id":"user_1","type":"ssh","fingerprint":"SHA256:abc","public_key":"ssh-ed25519 AAAAC3","created_at":"2026-01-02T03:04:05Z","revoked_at":"2026-01-05T00:00:00Z"}`)
}

func TestProofClaimGolden(t *testing.T) {
	golden(t, "ProofClaim", ProofClaim{
		ID:        "proof_1",
		UserID:    "user_1",
		Type:      "github",
		Target:    "https://github.com/ada",
		Status:    "verified",
		CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"id":"proof_1","user_id":"user_1","type":"github","target":"https://github.com/ada","status":"verified","created_at":"2026-01-02T03:04:05Z"}`)
}

func TestProfileLinkGolden(t *testing.T) {
	golden(t, "ProfileLink", ProfileLink{
		ID:        "link_1",
		Label:     "GitHub",
		URL:       "https://github.com/ada",
		Position:  2,
		CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"id":"link_1","label":"GitHub","url":"https://github.com/ada","position":2,"created_at":"2026-01-02T03:04:05Z"}`)
}

func TestProfilePageGolden(t *testing.T) {
	golden(t, "ProfilePage", ProfilePage{
		ID:          "profile_1",
		UserID:      "user_1",
		DisplayName: "Ada",
		Bio:         "hello",
		AvatarURL:   "https://cdn.example/avatar.png",
		IsPublished: true,
		UpdatedAt:   mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"id":"profile_1","user_id":"user_1","display_name":"Ada","bio":"hello","avatar_url":"https://cdn.example/avatar.png","is_published":true,"updated_at":"2026-01-02T03:04:05Z"}`)
}

func TestClientGolden(t *testing.T) {
	// The client secret must never appear in the wire format.
	golden(t, "Client", Client{
		ID:        "client_1",
		Name:      "Sovereign",
		Audience:  "https://sovereign.example",
		CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"id":"client_1","name":"Sovereign","audience":"https://sovereign.example","created_at":"2026-01-02T03:04:05Z"}`)
}

func TestAuditEntryGolden(t *testing.T) {
	golden(t, "AuditEntry", AuditEntry{
		ID:        "audit_1",
		Actor:     "user_1",
		Action:    "session.revoke",
		Resource:  "session:sess_1",
		Detail:    "admin action",
		CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"id":"audit_1","actor":"user_1","action":"session.revoke","resource":"session:sess_1","detail":"admin action","created_at":"2026-01-02T03:04:05Z"}`)
}

func TestBackupConfigGolden(t *testing.T) {
	golden(t, "BackupConfig", BackupConfig{
		Schedule:    "0 3 * * *",
		Destination: "s3://backups",
		Prefix:      "sovereign/",
		UpdatedAt:   mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"schedule":"0 3 * * *","destination":"s3://backups","prefix":"sovereign/","updated_at":"2026-01-02T03:04:05Z"}`)
}

func TestBackupRunGolden(t *testing.T) {
	run := BackupRun{
		ID:             "run_1",
		StartedAt:      mustTime(t, "2026-01-02T03:04:05Z"),
		FinishedAt:     nil,
		Status:         "running",
		Error:          nil,
		SizeBytes:      0,
		DestinationKey: "sovereign/run_1.tar.gz",
	}
	golden(t, "BackupRun running", run, `{"id":"run_1","started_at":"2026-01-02T03:04:05Z","finished_at":null,"status":"running","error":null,"size_bytes":0,"destination_key":"sovereign/run_1.tar.gz"}`)

	failed := run
	failed.FinishedAt = ptr(mustTime(t, "2026-01-02T03:05:00Z"))
	failed.Status = "failed"
	failed.Error = ptr("disk full")
	golden(t, "BackupRun failed", failed, `{"id":"run_1","started_at":"2026-01-02T03:04:05Z","finished_at":"2026-01-02T03:05:00Z","status":"failed","error":"disk full","size_bytes":0,"destination_key":"sovereign/run_1.tar.gz"}`)
}

func TestTakedownGolden(t *testing.T) {
	golden(t, "Takedown", Takedown{
		ID:        "td_1",
		Resource:  "user:user_1",
		Reason:    "spam",
		ActedBy:   "admin_1",
		CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}, `{"id":"td_1","resource":"user:user_1","reason":"spam","acted_by":"admin_1","created_at":"2026-01-02T03:04:05Z"}`)
}

func TestPendingDeletionGolden(t *testing.T) {
	pending := PendingDeletion{
		ID:          "pd_1",
		UserID:      "user_1",
		RequestedAt: mustTime(t, "2026-01-02T03:04:05Z"),
		Status:      "pending",
		ApprovedBy:  nil,
		ApprovedAt:  nil,
	}
	golden(t, "PendingDeletion pending", pending, `{"id":"pd_1","user_id":"user_1","requested_at":"2026-01-02T03:04:05Z","status":"pending","approved_by":null,"approved_at":null}`)

	approved := pending
	approved.Status = "approved"
	approved.ApprovedBy = ptr("admin_1")
	approved.ApprovedAt = ptr(mustTime(t, "2026-01-03T00:00:00Z"))
	golden(t, "PendingDeletion approved", approved, `{"id":"pd_1","user_id":"user_1","requested_at":"2026-01-02T03:04:05Z","status":"approved","approved_by":"admin_1","approved_at":"2026-01-03T00:00:00Z"}`)
}

func TestToSDocumentGolden(t *testing.T) {
	golden(t, "ToSDocument", ToSDocument{
		ID:          "tos_1",
		Version:     "2026-01-01",
		Content:     "Terms...",
		PublishedAt: mustTime(t, "2026-01-02T03:04:05Z"),
		PublishedBy: "admin_1",
	}, `{"id":"tos_1","version":"2026-01-01","content":"Terms...","published_at":"2026-01-02T03:04:05Z","published_by":"admin_1"}`)
}

func TestVersionGolden(t *testing.T) {
	golden(t, "Version full", Version{Version: "v1.2.3", Commit: "c172cf2", GoVersion: "go1.27"},
		`{"version":"v1.2.3","commit":"c172cf2","go_version":"go1.27"}`)

	golden(t, "Version minimal", Version{Version: "dev"},
		`{"version":"dev"}`)
}

func TestHealthGolden(t *testing.T) {
	golden(t, "Health ok", Health{Status: "ok"}, `{"status":"ok"}`)
	golden(t, "Health degraded", Health{Status: "degraded"}, `{"status":"degraded"}`)
}

func TestCapabilitiesGolden(t *testing.T) {
	golden(t, "Capabilities", Capabilities{
		Backup:   true,
		Atproto:  false,
		Solid:    true,
		IPFS:     false,
		Proofs:   true,
		WebAuthn: true,
		OIDC:     false,
	}, `{"backup":true,"atproto":false,"solid":true,"ipfs":false,"proofs":true,"webauthn":true,"oidc":false}`)
}

func TestErrorGolden(t *testing.T) {
	golden(t, "Error", Error{
		Type:     "https://sovereign.example/problems/not-found",
		Title:    "Not Found",
		Status:   404,
		Detail:   "user not found",
		Instance: "/api/v1/users/user_9",
	}, `{"type":"https://sovereign.example/problems/not-found","title":"Not Found","status":404,"detail":"user not found","instance":"/api/v1/users/user_9"}`)
}

func TestListGolden(t *testing.T) {
	golden(t, "List empty", List[User]{Data: []User{}, Offset: 0, Limit: 20, Total: 0},
		`{"data":[],"offset":0,"limit":20,"total":0}`)

	golden(t, "List non-empty", List[User]{Data: []User{{
		ID: "user_1", TenantID: "tenant_1", Email: "ada@example.com",
		CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
		UpdatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}}, Offset: 0, Limit: 1, Total: 1},
		`{"data":[{"id":"user_1","tenant_id":"tenant_1","email":"ada@example.com","display_name":"","is_admin":false,"tos_accepted":false,"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}],"offset":0,"limit":1,"total":1}`)
}

func TestCursorListGolden(t *testing.T) {
	next := "Y3Vyc29yXzI6YXVkaXRfMg"
	g := CursorList[AuditEntry]{Data: []AuditEntry{{
		ID: "audit_1", Actor: "user_1", Action: "login", CreatedAt: mustTime(t, "2026-01-02T03:04:05Z"),
	}}, NextCursor: ptr(next)}
	golden(t, "CursorList with next", g, `{"data":[{"id":"audit_1","actor":"user_1","action":"login","resource":"","detail":"","created_at":"2026-01-02T03:04:05Z"}],"next_cursor":"Y3Vyc29yXzI6YXVkaXRfMg"}`)

	golden(t, "CursorList end", CursorList[AuditEntry]{Data: []AuditEntry{}, NextCursor: nil},
		`{"data":[],"next_cursor":null}`)
}

// readSource reads dto.go so the no-map guard can assert on the source text.
func readSource(t *testing.T) (string, error) {
	t.Helper()
	b, err := os.ReadFile("dto.go")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// TestNoMapResponse guards the "no map[string]any" typing requirement: every
// response value in this package must marshal via a named struct, never a
// map. This is belt-and-braces on top of the DTO package having no map fields.
func TestNoMapResponse(t *testing.T) {
	if strings.Contains("", "map[string]interface{}") {
		t.Fatal("unreachable")
	}
	// The real guard: dto.go declares no map fields. A future regression that
	// adds one would still pass this; the golden tests plus code review cover
	// it. This test documents the invariant and fails if the source drifts.
	src, err := readSource(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"map[string]any", "map[string]interface{}", "map[string]string"} {
		if strings.Contains(src, bad) {
			t.Fatalf("dto.go contains forbidden %q; all responses must be named structs", bad)
		}
	}
}
