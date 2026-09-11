package atproto

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// testRecord is a minimal CborMarshaler for repo tests.
type testRecord struct {
	Text string `json:"text"`
}

func (r *testRecord) MarshalCBOR(w io.Writer) error {
	// Minimal CBOR encoding: a map with one key "text".
	_, err := w.Write([]byte{0xa1, 0x64, 't', 'e', 'x', 't', 0x64})
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(r.Text))
	return err
}

// TestRepoCommitSigning verifies repo creation, record write, and commit signing.
func TestRepoCommitSigning(t *testing.T) {
	ctx := context.Background()
	sk, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	did := "did:plc:abc123"

	r, err := NewRepo(ctx, did, sk, filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatalf("NewRepo: %v", err)
	}

	// Create a record.
	cid, tid, err := r.CreateRecord(ctx, "app.bsky.feed.post", &testRecord{Text: "hello"})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if cid == "" || tid == "" {
		t.Fatalf("empty cid/tid: %q %q", cid, tid)
	}

	// Commit.
	commitCid, rev, err := r.Commit(ctx)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if commitCid == "" || rev == "" {
		t.Fatalf("empty commit cid/rev: %q %q", commitCid, rev)
	}

	// Verify the commit signature with the public key.
	pub, err := sk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.VerifyCommit(pub); err != nil {
		t.Fatalf("VerifyCommit: %v", err)
	}

	// GetRecordBytes reads the record back (raw bytes, no decode).
	_, data, err := r.GetRecordBytes(ctx, "app.bsky.feed.post/"+tid)
	if err != nil {
		t.Fatalf("GetRecordBytes: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("GetRecordBytes returned empty data")
	}
}

// TestRepoVerifyCommitWrongKey verifies a wrong key fails verification.
func TestRepoVerifyCommitWrongKey(t *testing.T) {
	ctx := context.Background()
	sk, _ := atcrypto.GeneratePrivateKeyP256()
	other, _ := atcrypto.GeneratePrivateKeyP256()

	r, err := NewRepo(ctx, "did:plc:abc123", sk, filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.CreateRecord(ctx, "app.bsky.feed.post", &testRecord{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	otherPub, _ := other.PublicKey()
	if err := r.VerifyCommit(otherPub); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

// TestRepoWriteCAREmptyRepo verifies WriteCAR errors on an uncommitted repo
// (no root). The full CAR export path (decode of committed blocks) is covered
// by Step 7 of the steps5-8-hardening plan, which replaces the byte-string
// record encoding with proper DAG-CBOR (A6).
func TestRepoWriteCAREmptyRepo(t *testing.T) {
	ctx := context.Background()
	sk, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRepo(ctx, "did:plc:abc123", sk, filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteCAR(ctx, io.Discard); err == nil {
		t.Fatal("WriteCAR on empty repo succeeded, want error")
	}
}

// TestRepoPersistenceAcrossReopen verifies the repo survives a blockstore
// reopen (durable storage).
func TestRepoPersistenceAcrossReopen(t *testing.T) {
	ctx := context.Background()
	sk, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "repo.db")

	r, err := NewRepo(ctx, "did:plc:abc123", sk, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.CreateRecord(ctx, "app.bsky.feed.post", &testRecord{Text: "persistent"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the same blockstore path.
	r2, err := NewRepo(ctx, "did:plc:abc123", sk, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r2.Close() }()
	// The repo should still have its commit (not empty).
	if sc := r2.SignedCommit(); sc.Did == "" {
		t.Fatal("repo lost its commit after reopen")
	}
}
