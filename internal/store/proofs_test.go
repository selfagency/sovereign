package store

import (
	"context"
	"testing"
	"time"
)

// TestListProofClaims verifies a tenant's claims are returned in creation
// order and an empty tenant yields an empty list.
func TestListProofClaims(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")

	now := time.Now().UTC()
	claims := []*ProofClaim{
		{ID: "c1", TenantID: "t1", AccountID: "u1", AnchorType: "dns", AnchorValue: "alice.example.com", Service: "github", ClaimLocation: "https://github.com/alice", ExpectedToken: "tok1", Status: "pending", CreatedAt: now},
		{ID: "c2", TenantID: "t1", AccountID: "u1", AnchorType: "dns", AnchorValue: "alice.example.com", Service: "keyoxide", ClaimLocation: "https://keyoxide.org/alice", ExpectedToken: "tok2", Status: "verified", CreatedAt: now.Add(time.Second)},
	}
	for _, c := range claims {
		if err := s.CreateProofClaim(ctx, c); err != nil {
			t.Fatalf("CreateProofClaim %s: %v", c.ID, err)
		}
	}

	got, err := s.ListProofClaims(ctx, "t1")
	if err != nil {
		t.Fatalf("ListProofClaims: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListProofClaims = %d claims, want 2", len(got))
	}
	if got[0].ID != "c1" || got[1].ID != "c2" {
		t.Fatalf("claims out of order: %+v", got)
	}
	if got[1].Status != "verified" {
		t.Fatalf("claim c2 status = %q, want verified", got[1].Status)
	}

	// Another tenant has no claims.
	empty, err := s.ListProofClaims(ctx, "t2")
	if err != nil {
		t.Fatalf("ListProofClaims t2: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListProofClaims t2 = %d claims, want 0", len(empty))
	}
}
