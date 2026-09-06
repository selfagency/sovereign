package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAPITokenCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	raw, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	tok := &APIToken{
		ID:        "t1",
		UserID:    "u1",
		TokenHash: HashAPIToken(raw),
		FamilyID:  "fam1",
		Name:      "ci",
		Scopes:    []string{"keys:read", "profile:read"},
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	if err := s.CreateAPIToken(ctx, tok); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	// Get by hash.
	got, err := s.GetAPIToken(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("GetAPIToken: %v", err)
	}
	if got.ID != "t1" || len(got.Scopes) != 2 || got.Scopes[0] != "keys:read" {
		t.Fatalf("GetAPIToken = %+v", got)
	}

	// List (scoped to user).
	list, err := s.ListAPITokens(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAPITokens = %d, %v", len(list), err)
	}

	// Touch records last_used_at.
	if err := s.TouchAPIToken(ctx, tok.TokenHash); err != nil {
		t.Fatalf("TouchAPIToken: %v", err)
	}
	got, _ = s.GetAPIToken(ctx, tok.TokenHash)
	if got.LastUsedAt == nil {
		t.Fatal("TouchAPIToken did not set last_used_at")
	}

	// Revoke (by family, scoped to user).
	if err := s.RevokeAPITokenFamily(ctx, "u1", "fam1"); err != nil {
		t.Fatalf("RevokeAPITokenFamily: %v", err)
	}
	if _, err := s.GetAPIToken(ctx, tok.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAPIToken after revoke = %v, want ErrNotFound", err)
	}
}

func TestAPITokenRevokeScopedToUser(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Two users, each with a token in a distinct family.
	for _, u := range []string{"u1", "u2"} {
		if err := s.CreateAPIToken(ctx, &APIToken{
			ID: "t-" + u, UserID: u, TokenHash: HashAPIToken(u), FamilyID: "fam-" + u,
			Scopes: []string{"self"}, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Revoking u2's family with u1's identity must fail and leave it intact.
	if err := s.RevokeAPITokenFamily(ctx, "u1", "fam-u2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-user revoke = %v, want ErrNotFound", err)
	}
	if _, err := s.GetAPIToken(ctx, HashAPIToken("u2")); err != nil {
		t.Fatalf("u2 token should remain: %v", err)
	}
	// Own family revokes cleanly; every member of the family is revoked.
	if err := s.CreateAPIToken(ctx, &APIToken{
		ID: "t-mine", UserID: "u1", TokenHash: HashAPIToken("mine1"), FamilyID: "fam-u1",
		Scopes: []string{"self"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAPITokenFamily(ctx, "u1", "fam-u1"); err != nil {
		t.Fatalf("own family revoke: %v", err)
	}
	for _, raw := range []string{"u1", "mine1"} {
		if _, err := s.GetAPIToken(ctx, HashAPIToken(raw)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("family member %q should be revoked, got %v", raw, err)
		}
	}
}

func TestAPITokenHashNotPlaintext(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	raw := "super-secret-token-value"
	if err := s.CreateAPIToken(ctx, &APIToken{
		ID: "t1", UserID: "u1", TokenHash: HashAPIToken(raw), FamilyID: "f",
		Scopes: []string{"self"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAPIToken(ctx, HashAPIToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.TokenHash, raw) || got.TokenHash == raw {
		t.Fatalf("stored token_hash leaks plaintext: %q", got.TokenHash)
	}
}
