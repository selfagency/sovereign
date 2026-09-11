package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// produceBackup writes a gzip-compressed tar of the data directory (the
// identity database, blobs, and per-tenant atproto repos) to a pipe and
// returns the read end. The Scheduler's BackupFn consumes it; the producer
// runs in a goroutine so the scheduler can stream to the destination without
// buffering the whole archive in memory.
//
// The archive includes the SQLite WAL/SHM sidecars so the database is
// recoverable from the snapshot (SQLite replays the WAL on open).
func produceBackup(ctx context.Context, dataDir string) (io.Reader, error) {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeBackupArchive(ctx, dataDir, pw))
	}()
	return pr, nil
}

// writeBackupArchive writes a gzip tar of dataDir to w. Each file is copied
// to a temp file first so the tar header size matches the bytes actually
// written — the SQLite DB can grow between stat and read while the server is
// running, which would otherwise abort the archive with "write too long".
func writeBackupArchive(ctx context.Context, dataDir string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	root, err := filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("backup: resolve data dir: %w", err)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root || d.IsDir() {
			return nil
		}
		// Never follow symlinks: a symlink planted in the data dir would
		// otherwise pull arbitrary files into the backup (TOCTOU traversal).
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Snapshot the file to a temp so its size is stable while tarring.
		tmp, err := os.CreateTemp("", "sovereign-backup-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		defer func() { _ = os.Remove(tmpName) }()
		f, err := os.Open(path) // #nosec G304 G122 -- path is under the operator's data dir; symlinks are skipped above
		if err != nil {
			_ = tmp.Close()
			return err
		}
		if _, err := io.Copy(tmp, f); err != nil {
			_ = f.Close()
			_ = tmp.Close()
			return err
		}
		_ = f.Close()
		if err := tmp.Close(); err != nil {
			return err
		}
		info, err := os.Stat(tmpName)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		tf, err := os.Open(tmpName) // #nosec G304 -- path is from os.CreateTemp
		if err != nil {
			return err
		}
		defer func() { _ = tf.Close() }()
		if _, err := io.Copy(tw, tf); err != nil {
			return err
		}
		return nil
	})
}
