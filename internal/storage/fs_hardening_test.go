package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errReader fails after the first byte, simulating a mid-write failure.
type errReader struct{ read bool }

func (e *errReader) Read(p []byte) (int, error) {
	if e.read {
		return 0, errors.New("simulated read failure")
	}
	e.read = true
	p[0] = 'x'
	return 1, nil
}

// TestFSPutAtomicOnFailure verifies a failed Put leaves no file at the target
// key (crash-safety: temp file + rename, never a partial write at the key).
func TestFSPutAtomicOnFailure(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	_, err := f.Put(context.Background(), "sub/blob.bin", &errReader{}, "application/octet-stream")
	if err == nil {
		t.Fatal("Put with failing reader succeeded, want error")
	}
	if _, err := os.Stat(filepath.Join(root, "sub", "blob.bin")); err == nil {
		t.Fatal("failed Put left a partial file at the key")
	}
}

// TestFSPutNoTempLeftBehind verifies a successful Put leaves no temp files.
func TestFSPutNoTempLeftBehind(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	if _, err := f.Put(context.Background(), "a/b.bin", bytes.NewReader([]byte("data")), "text/plain"); err != nil {
		t.Fatal(err)
	}
	var names []string
	_ = filepath.Walk(root, func(p string, _ os.FileInfo, _ error) error {
		names = append(names, filepath.Base(p))
		return nil
	})
	for _, n := range names {
		if strings.HasPrefix(n, ".tmp") || strings.HasSuffix(n, ".tmp") {
			t.Fatalf("temp file left behind: %v", names)
		}
	}
}

// TestFSGetSurfacesSidecarError verifies a sidecar read failure (not
// not-found) is surfaced rather than silently returning an empty content type.
func TestFSGetSurfacesSidecarError(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	if _, err := f.Put(context.Background(), "blob", bytes.NewReader([]byte("x")), "text/plain"); err != nil {
		t.Fatal(err)
	}
	// Replace the sidecar with a directory so reading it fails.
	meta := filepath.Join(root, "blob.meta")
	if err := os.Remove(meta); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(meta, 0o750); err != nil {
		t.Fatal(err)
	}
	rc, _, err := f.Get(context.Background(), "blob")
	if err == nil {
		_ = rc.Close()
		t.Fatal("Get with unreadable sidecar succeeded, want error")
	}
}

// TestFSListReturnsContentTypes verifies List populates ContentType from the
// sidecar rather than returning an empty string.
func TestFSListReturnsContentTypes(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	if _, err := f.Put(context.Background(), "p/a.png", bytes.NewReader([]byte("a")), "image/png"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Put(context.Background(), "p/b.txt", bytes.NewReader([]byte("b")), "text/plain"); err != nil {
		t.Fatal(err)
	}
	blobs, err := f.List(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, b := range blobs {
		got[b.Key] = b.ContentType
	}
	if got["p/a.png"] != "image/png" {
		t.Fatalf("a.png content type = %q, want image/png (all: %v)", got["p/a.png"], got)
	}
	if got["p/b.txt"] != "text/plain" {
		t.Fatalf("b.txt content type = %q, want text/plain (all: %v)", got["p/b.txt"], got)
	}
}

// TestFSPutHonorsContext verifies a canceled context aborts the Put.
func TestFSPutHonorsContext(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.Put(ctx, "blob", bytes.NewReader([]byte("x")), "text/plain")
	if err == nil {
		t.Fatal("Put with canceled context succeeded, want error")
	}
}

// TestFSSymlinkEscape verifies a symlink inside the root pointing outside is
// not followed for read or write (path traversal via symlink).
func TestFSSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plant a symlink inside root that points at the outside dir.
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	f := &FS{Root: root}

	// Write through the symlink must not escape root.
	if _, err := f.Put(context.Background(), "link/evil.txt", bytes.NewReader([]byte("evil")), "text/plain"); err == nil {
		if _, err := os.Stat(filepath.Join(outside, "evil.txt")); err == nil {
			t.Fatal("Put escaped root through a symlink")
		}
	}

	// Read through the symlink must not reach the outside file.
	rc, _, err := f.Get(context.Background(), "link/secret.txt")
	if err == nil {
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(b) == "secret" {
			t.Fatal("Get read a file outside root through a symlink")
		}
	}
}

// TestFSRejectsControlChars verifies keys with NUL/newline are rejected.
func TestFSRejectsControlChars(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	for _, key := range []string{"a\x00b", "a\nb", "a\rb"} {
		if _, err := f.Put(context.Background(), key, bytes.NewReader([]byte("x")), "text/plain"); err == nil {
			t.Fatalf("Put(%q) succeeded, want rejection", key)
		}
	}
}

// TestFSOpsHonorContext verifies Get/Delete/List abort on a canceled context.
func TestFSOpsHonorContext(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	if _, err := f.Put(context.Background(), "blob", bytes.NewReader([]byte("x")), "text/plain"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := f.Get(ctx, "blob"); err == nil {
		t.Fatal("Get with canceled context succeeded, want error")
	}
	if err := f.Delete(ctx, "blob"); err == nil {
		t.Fatal("Delete with canceled context succeeded, want error")
	}
	if _, err := f.List(ctx, ""); err == nil {
		t.Fatal("List with canceled context succeeded, want error")
	}
}

// TestFSOpsRejectInvalidKey verifies Get/Delete/List reject invalid keys.
func TestFSOpsRejectInvalidKey(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	if _, _, err := f.Get(context.Background(), "a\x00b"); err == nil {
		t.Fatal("Get with NUL key succeeded, want error")
	}
	if err := f.Delete(context.Background(), "a\x00b"); err == nil {
		t.Fatal("Delete with NUL key succeeded, want error")
	}
	if _, err := f.List(context.Background(), "a\x00b"); err == nil {
		t.Fatal("List with NUL prefix succeeded, want error")
	}
}

// TestFSGetMissing verifies Get returns ErrNotFound for a missing key.
func TestFSGetMissing(t *testing.T) {
	root := t.TempDir()
	f := &FS{Root: root}
	if _, _, err := f.Get(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}
