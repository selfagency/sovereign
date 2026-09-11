package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FS is a local-filesystem Backend. Keys map to paths under Root.
// Safe for concurrent use: each operation opens its own file handle.
//
// All operations are scoped with os.Root (Go 1.24+) so a symlink planted
// under Root cannot escape it for reads or writes.
type FS struct {
	Root string
}

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("storage: not found")

// validKey rejects empty keys and control characters (NUL, CR, LF, ...).
func validKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// relKey normalizes key to a slash-separated path relative to Root, with any
// traversal cleaned away. os.Root still refuses to escape; this keeps the
// on-disk layout stable.
func relKey(key string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+key)), "/")
}

// openRoot opens the FS root for scoped operations.
func (f *FS) openRoot() (*os.Root, error) {
	if err := os.MkdirAll(f.Root, 0o750); err != nil {
		return nil, err
	}
	return os.OpenRoot(f.Root)
}

// ctxReader aborts a copy when ctx is canceled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// Put stores r under key, persisting contentType in a sidecar file. The write
// is crash-safe: data goes to a temp file, is fsynced, then renamed into
// place, so a crash never leaves a partial file at the key.
func (f *FS) Put(ctx context.Context, key string, r io.Reader, contentType string) (Blob, error) {
	if err := ctx.Err(); err != nil {
		return Blob{}, err
	}
	if !validKey(key) {
		return Blob{}, ErrInvalidKey
	}
	root, err := f.openRoot()
	if err != nil {
		return Blob{}, err
	}
	defer func() { _ = root.Close() }()

	rel := relKey(key)
	if dir := filepath.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, 0o750); err != nil {
			return Blob{}, err
		}
	}
	n, err := writeFileSync(root, rel, ctxReader{ctx: ctx, r: r})
	if err != nil {
		return Blob{}, err
	}
	if _, err := writeFileSync(root, rel+".meta", strings.NewReader(contentType)); err != nil {
		return Blob{}, err
	}
	return Blob{Key: key, ContentType: contentType, Size: n}, nil
}

// writeFileSync writes src to a temp file under root, fsyncs it, then renames
// it onto name. Returns the number of bytes written.
func writeFileSync(root *os.Root, name string, src io.Reader) (int64, error) {
	tmp := name + ".tmp"
	fh, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	cleanup := func() {
		_ = fh.Close()
		_ = root.Remove(tmp)
	}
	n, err := io.Copy(fh, src)
	if err != nil {
		cleanup()
		return 0, err
	}
	if err := fh.Sync(); err != nil {
		cleanup()
		return 0, err
	}
	if err := fh.Close(); err != nil {
		_ = root.Remove(tmp)
		return 0, err
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// Get returns the stored object for key.
func (f *FS) Get(ctx context.Context, key string) (io.ReadCloser, Blob, error) {
	if err := ctx.Err(); err != nil {
		return nil, Blob{}, err
	}
	if !validKey(key) {
		return nil, Blob{}, ErrInvalidKey
	}
	root, err := os.OpenRoot(f.Root)
	if err != nil {
		return nil, Blob{}, err
	}
	defer func() { _ = root.Close() }()

	rel := relKey(key)
	fh, err := root.Open(rel)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, Blob{}, ErrNotFound
		}
		return nil, Blob{}, err
	}
	st, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, Blob{}, err
	}
	ct, err := readSidecar(root, rel)
	if err != nil {
		_ = fh.Close()
		return nil, Blob{}, err
	}
	return fh, Blob{Key: key, ContentType: ct, Size: st.Size()}, nil
}

// readSidecar reads the content-type sidecar. A missing sidecar is not an
// error (older blobs predate it); any other failure is surfaced.
func readSidecar(root *os.Root, rel string) (string, error) {
	b, err := root.ReadFile(rel + ".meta")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

// Delete removes the stored object for key.
func (f *FS) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKey(key) {
		return ErrInvalidKey
	}
	root, err := os.OpenRoot(f.Root)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	rel := relKey(key)
	err = root.Remove(rel)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	// Best-effort removal of the sidecar metadata file.
	_ = root.Remove(rel + ".meta")
	return err
}

// List returns all stored objects under prefix.
func (f *FS) List(ctx context.Context, prefix string) ([]Blob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validKey(prefix) {
		return nil, ErrInvalidKey
	}
	root, err := os.OpenRoot(f.Root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	dir := relKey(prefix)
	var out []Blob
	walkErr := filepath.WalkDir(filepath.Join(f.Root, filepath.FromSlash(dir)), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil // empty prefix
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Never follow symlinks during a listing.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if strings.HasSuffix(p, ".meta") || strings.HasSuffix(p, ".tmp") {
			return nil // sidecars and in-flight writes are not blobs
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(f.Root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		ct, err := readSidecar(root, rel)
		if err != nil {
			return err
		}
		out = append(out, Blob{Key: rel, ContentType: ct, Size: info.Size()})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}

var _ Backend = (*FS)(nil)
