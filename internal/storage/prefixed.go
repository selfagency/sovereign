package storage

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"
)

// Prefixed wraps a Backend and prefixes every key with a namespace. This is
// how multi-tenant isolation is enforced on a shared backend: each tenant's
// keys live under "<prefix>/", so tenants cannot read or write each other's
// data (IDOR boundary). It works for both FS (subdirectory) and S3 (key
// prefix) backends.
type Prefixed struct {
	Backend Backend
	Prefix  string
}

// ErrInvalidKey is returned when a key would escape the tenant namespace.
var ErrInvalidKey = errors.New("storage: invalid key")

// key joins the prefix and key, rejecting any key that would escape the
// namespace. path.Join silently cleans traversal ("a" + "/../b/x" -> "b/x"),
// which would let a tenant read or write another tenant's blobs — so we
// validate the key before joining.
func (p *Prefixed) key(key string) (string, error) {
	if key == "" {
		return "", ErrInvalidKey
	}
	// Reject absolute paths and any traversal component.
	if strings.HasPrefix(key, "/") {
		return "", ErrInvalidKey
	}
	for _, part := range strings.Split(key, "/") {
		if part == ".." || part == "." {
			return "", ErrInvalidKey
		}
	}
	// Reject NUL and other control characters (path.Join would pass them
	// through to the FS).
	if !validKey(key) {
		return "", ErrInvalidKey
	}
	return path.Join(p.Prefix, key), nil
}

// Put stores r under the prefixed key.
func (p *Prefixed) Put(ctx context.Context, key string, r io.Reader, contentType string) (Blob, error) {
	k, err := p.key(key)
	if err != nil {
		return Blob{}, err
	}
	return p.Backend.Put(ctx, k, r, contentType)
}

// Get returns the stored object for the prefixed key.
func (p *Prefixed) Get(ctx context.Context, key string) (io.ReadCloser, Blob, error) {
	k, err := p.key(key)
	if err != nil {
		return nil, Blob{}, err
	}
	return p.Backend.Get(ctx, k)
}

// Delete removes the stored object for the prefixed key.
func (p *Prefixed) Delete(ctx context.Context, key string) error {
	k, err := p.key(key)
	if err != nil {
		return err
	}
	return p.Backend.Delete(ctx, k)
}

// List returns all stored objects under the prefixed key.
func (p *Prefixed) List(ctx context.Context, prefix string) ([]Blob, error) {
	k, err := p.key(prefix)
	if err != nil {
		return nil, err
	}
	return p.Backend.List(ctx, k)
}

var _ Backend = (*Prefixed)(nil)
