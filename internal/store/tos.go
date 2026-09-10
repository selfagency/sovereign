package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ToSDocument is a published Terms of Service version stored in the
// tos_documents table.
type ToSDocument struct {
	ID          string
	Version     string
	Content     string
	PublishedAt time.Time
	PublishedBy string
}

// GetLatestToSDocument returns the most recently published ToS document, or
// ErrNotFound when none has been published yet. published_at is stored as an
// RFC 3339 TEXT string (the tos_documents column is TEXT affinity), so it is
// parsed back into a time.Time on read.
func (s *Store) GetLatestToSDocument(ctx context.Context) (*ToSDocument, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, version, content, published_at, published_by
		 FROM tos_documents ORDER BY published_at DESC, rowid DESC LIMIT 1`)
	var d ToSDocument
	var publishedAt string
	var by sql.NullString
	err := row.Scan(&d.ID, &d.Version, &d.Content, &publishedAt, &by)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get latest tos document: %w", err)
	}
	if publishedAt != "" {
		if t, perr := time.Parse(time.RFC3339, publishedAt); perr == nil {
			d.PublishedAt = t
		}
	}
	d.PublishedBy = by.String
	return &d, nil
}

// UpsertToSDocument inserts a new published ToS version, returning the stored
// document. Each publish creates a new row keyed by its ID so the full version
// history is retained. published_at is stored as an RFC 3339 string.
func (s *Store) UpsertToSDocument(ctx context.Context, d *ToSDocument) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tos_documents (id, version, content, published_at, published_by)
		 VALUES (?, ?, ?, ?, ?)`,
		d.ID, d.Version, d.Content, d.PublishedAt.UTC().Format(time.RFC3339), d.PublishedBy)
	if err != nil {
		return fmt.Errorf("store: upsert tos document: %w", err)
	}
	return nil
}
