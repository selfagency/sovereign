package store

import (
	"context"
	"testing"
	"time"
)

// TestClosedStoreErrorBranches drives every store method's SQL error branch by
// closing the DB first: each call must return an error, covering the
// `if err != nil { return fmt.Errorf(...) }` paths that happy-path tests skip.
func TestClosedStoreErrorBranches(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Seed minimal rows so methods that query-then-write reach their write.
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Each call must error on the closed DB.
	calls := []struct {
		name string
		fn   func() error
	}{
		{"SetToSAccepted", func() error { return s.SetToSAccepted(ctx, "u1", true) }},
		{"SetPasskeySetup", func() error { return s.SetPasskeySetup(ctx, "u1", true) }},
		{"MarkInviteTokenUsed", func() error { return s.MarkInviteTokenUsed(ctx, "tok") }},
		{"CreateInviteToken", func() error { return s.CreateInviteToken(ctx, &InviteToken{ID: "i", TokenHash: "h", UserID: "u1"}) }},
		{"AddWebAuthnCredential", func() error { return s.AddWebAuthnCredential(ctx, &WebAuthnCredential{ID: "w", UserID: "u1"}) }},
		{"UpdateWebAuthnSignCount", func() error { return s.UpdateWebAuthnSignCount(ctx, "w", 1) }},
		{"AppendAudit", func() error { return s.AppendAudit(ctx, &AuditEntry{ID: "a", Actor: "u1"}) }},
		{"UpsertBackupConfig", func() error { return s.UpsertBackupConfig(ctx, "s", "d", "p") }},
		{"CreateBackupRun", func() error { return s.CreateBackupRun(ctx, &BackupRun{ID: "r"}) }},
		{"UpdateBackupRun", func() error { return s.UpdateBackupRun(ctx, "r", "ok", "", 0, "k") }},
		{"CreateBackupRestore", func() error { return s.CreateBackupRestore(ctx, &BackupRestore{ID: "r"}) }},
		{"UpdateBackupRestore", func() error { return s.UpdateBackupRestore(ctx, "r", "ok", "") }},
		{"RevokePublicKey", func() error { return s.RevokePublicKey(ctx, "t1", "u1", "k") }},
		{"DeletePublicKey", func() error { return s.DeletePublicKey(ctx, "t1", "u1", "k") }},
		{"AddIPFSPin", func() error { return s.AddIPFSPin(ctx, "cid", "pinned") }},
		{"DeleteProfileLink", func() error { return s.DeleteProfileLink(ctx, "p", "l") }},
		{"DeleteProfilePage", func() error { return s.DeleteProfilePage(ctx, "t1") }},
		{"UpdateProofClaimStatus", func() error { return s.UpdateProofClaimStatus(ctx, "t1", "c", "verified", "") }},
		{"DeleteProofClaim", func() error { return s.DeleteProofClaim(ctx, "t1", "u1", "c") }},
		{"DeleteTenant", func() error { return s.DeleteTenant(ctx, "t1") }},
		{"RevokeAPITokenFamily", func() error { return s.RevokeAPITokenFamily(ctx, "u1", "f") }},
		{"DeleteUser", func() error { return s.DeleteUser(ctx, "u1") }},
		{"SetUserAdmin", func() error { return s.SetUserAdmin(ctx, "u1", true) }},
		{"SetUserDisplayName", func() error { return s.SetUserDisplayName(ctx, "u1", "x") }},
		{"UpdateProfileLink", func() error {
			return s.UpdateProfileLink(ctx, "p", "l", &ProfileLink{ID: "l", ProfilePageID: "p"})
		}},
		{"CreateTenant", func() error { return s.CreateTenant(ctx, &Tenant{ID: "t2", Handle: "t2"}) }},
		{"CreateUser", func() error { return s.CreateUser(ctx, &User{ID: "u2", TenantID: "t1", Handle: "bob"}) }},
		{"CreateClient", func() error { return s.CreateClient(ctx, &Client{ID: "c"}) }},
		{"SetClientSecret", func() error { return s.SetClientSecret(ctx, "c", "s") }},
		{"DeleteClient", func() error { return s.DeleteClient(ctx, "c") }},
		{"CreateProofClaim", func() error { return s.CreateProofClaim(ctx, &ProofClaim{ID: "c", TenantID: "t1", AccountID: "u1"}) }},
		{"CreatePendingDeletion", func() error { _, err := s.CreatePendingDeletion(ctx, "u1"); return err }},
		{"ApprovePendingDeletion", func() error { return s.ApprovePendingDeletion(ctx, "d", "admin") }},
		{"RejectPendingDeletion", func() error { return s.RejectPendingDeletion(ctx, "d", "admin") }},
		{"CreateAPIToken", func() error { return s.CreateAPIToken(ctx, &APIToken{ID: "t", UserID: "u1"}) }},
		{"CreateSession", func() error { _, err := s.CreateSession(ctx, "u1", "h", 0, "", ""); return err }},
		{"RevokeUserSessions", func() error { return s.RevokeUserSessions(ctx, "u1") }},
		{"RevokeUserSessionsExcept", func() error { return s.RevokeUserSessionsExcept(ctx, "u1", "s") }},
		{"TouchSession", func() error { return s.TouchSession(ctx, "s", time.Now()) }},
		{"UpsertProfilePage", func() error { return s.UpsertProfilePage(ctx, &ProfilePage{ID: "p", TenantID: "t1", AccountID: "u1"}) }},
		{"UpsertToSDocument", func() error { return s.UpsertToSDocument(ctx, &ToSDocument{ID: "t", Version: "v1"}) }},
		{"CreateTakedown", func() error { return s.CreateTakedown(ctx, &Takedown{ID: "t", Resource: "r"}) }},
		{"DeleteTakedown", func() error { return s.DeleteTakedown(ctx, "t") }},
		{"SaveAuthSigningKey", func() error { return s.SaveAuthSigningKey(ctx, AuthSigningKey{}) }},
		{"SaveAuthRefreshToken", func() error { return s.SaveAuthRefreshToken(ctx, &AuthRefreshToken{}) }},
		{"RevokeAuthRefreshTokenFamily", func() error { return s.RevokeAuthRefreshTokenFamily(ctx, "f") }},
		{"DeleteAuthRefreshToken", func() error { return s.DeleteAuthRefreshToken(ctx, "t") }},
		{"ListAllUsersPage", func() error { _, _, err := s.ListAllUsersPage(ctx, 10, 0); return err }},
		{"ListUsersPage", func() error { _, _, err := s.ListUsersPage(ctx, "t1", 10, 0); return err }},
		{"ListAuditAllPage", func() error { _, _, err := s.ListAuditAllPage(ctx, 10, 0); return err }},
		{"ListAuditPage", func() error { _, _, err := s.ListAuditPage(ctx, "t1", 10, 0); return err }},
		{"ListClientsPage", func() error { _, _, err := s.ListClientsPage(ctx, 10, 0); return err }},
		{"ListTenantsPage", func() error { _, _, err := s.ListTenantsPage(ctx, 10, 0); return err }},
		{"DeleteWebAuthnCredential", func() error { return s.DeleteWebAuthnCredential(ctx, "u1", []byte("w")) }},
		{"RotateAuthRefreshToken", func() error { return s.RotateAuthRefreshToken(ctx, "f", &AuthRefreshToken{}) }},
		{"ListBackupRuns", func() error { _, _, err := s.ListBackupRuns(ctx, 10, 0); return err }},
		{"ListBackupRestores", func() error { _, _, err := s.ListBackupRestores(ctx, 10, 0); return err }},
		{"ListProofClaims", func() error { _, err := s.ListProofClaims(ctx, "t1"); return err }},
		{"ListUserSessions", func() error { _, err := s.ListUserSessions(ctx, "u1"); return err }},
		{"ListAPITokens", func() error { _, err := s.ListAPITokens(ctx, "u1"); return err }},
		{"ListTakedowns", func() error { _, _, err := s.ListTakedowns(ctx, 10, 0); return err }},
		{"ListPendingDeletions", func() error { _, _, err := s.ListPendingDeletions(ctx, 10, 0); return err }},
		{"ListIPFSPins", func() error { _, err := s.ListIPFSPins(ctx); return err }},
		{"GetLatestToSDocument", func() error { _, err := s.GetLatestToSDocument(ctx); return err }},
		{"GetProfilePage", func() error { _, err := s.GetProfilePage(ctx, "t1"); return err }},
		{"ListProfileLinks", func() error { _, err := s.ListProfileLinks(ctx, "p"); return err }},
		{"GetPublicKey", func() error { _, err := s.GetPublicKey(ctx, "t1", "k"); return err }},
		{"ListPublicKeys", func() error { _, err := s.ListPublicKeys(ctx, "t1", "ssh"); return err }},
		{"GetProofClaim", func() error { _, err := s.GetProofClaim(ctx, "t1", "c"); return err }},
		{"GetTenantByID", func() error { _, err := s.GetTenantByID(ctx, "t1"); return err }},
		{"GetTenantByDID", func() error { _, err := s.GetTenantByDID(ctx, "did:web:t1"); return err }},
		{"UserByID", func() error { _, err := s.UserByID(ctx, "u1"); return err }},
		{"UserByHandle", func() error { _, err := s.UserByHandle(ctx, "t1", "alice"); return err }},
		{"ClientByID", func() error { _, err := s.ClientByID(ctx, "c"); return err }},
		{"GetSessionByTokenHash", func() error { _, err := s.GetSessionByTokenHash(ctx, "h"); return err }},
		{"GetSessionByID", func() error { _, err := s.GetSessionByID(ctx, "s"); return err }},
		{"GetAPIToken", func() error { _, err := s.GetAPIToken(ctx, "h"); return err }},
		{"GetAuthSigningKey", func() error { _, err := s.GetAuthSigningKey(ctx, "id"); return err }},
		{"GetAuthRefreshToken", func() error { _, err := s.GetAuthRefreshToken(ctx, "t"); return err }},
		{"InviteTokenByHash", func() error { _, err := s.InviteTokenByHash(ctx, "h"); return err }},
		{"GetWebAuthnCredential", func() error { _, err := s.GetWebAuthnCredential(ctx, []byte("w")); return err }},
		{"PendingDeletionByUser", func() error { _, err := s.PendingDeletionByUser(ctx, "u1"); return err }},
		{"PendingDeletionByID", func() error { _, err := s.PendingDeletionByID(ctx, "d"); return err }},
		{"GetBackupConfig", func() error { _, err := s.GetBackupConfig(ctx); return err }},
		{"GetIPFSPin", func() error { _, err := s.GetIPFSPin(ctx, "cid"); return err }},
		{"AccountByWebID", func() error { _, err := s.AccountByWebID(ctx, "webid"); return err }},
		{"CreateAccount", func() error { return s.CreateAccount(ctx, &Account{ID: "a", TenantID: "t1"}) }},
		{"ReorderProfileLinks", func() error { return s.ReorderProfileLinks(ctx, "p", []string{"a", "b"}) }},
		{"ListAudit", func() error { _, err := s.ListAudit(ctx, "t1", 10); return err }},
		{"AppendAudit", func() error { return s.AppendAudit(ctx, &AuditEntry{ID: "a2", Actor: "u1"}) }},
	}
	for _, c := range calls {
		if err := c.fn(); err == nil {
			t.Errorf("%s: want error on closed store, got nil", c.name)
		}
	}
}
