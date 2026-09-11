package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestProduceBackup verifies the producer archives every file under the data
// dir (db + blobs + atproto repos) as a readable gzip tar.
func TestProduceBackup(t *testing.T) {
	dir := t.TempDir()
	// Lay out a data dir: identity.db, blobs/, atproto/.
	if err := os.WriteFile(filepath.Join(dir, "identity.db"), []byte("db-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", "b1"), []byte("blob-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "atproto"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "atproto", "did-web-alice.db"), []byte("repo-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := produceBackup(context.Background(), dir)
	if err != nil {
		t.Fatalf("produceBackup: %v", err)
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		got[hdr.Name] = string(b)
	}
	for name, want := range map[string]string{
		"identity.db":              "db-bytes",
		"blobs/b1":                 "blob-bytes",
		"atproto/did-web-alice.db": "repo-bytes",
	} {
		if got[name] != want {
			t.Fatalf("archive[%q] = %q, want %q (all: %v)", name, got[name], want, got)
		}
	}
}
