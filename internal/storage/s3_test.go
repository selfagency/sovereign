package storage

import (
	"context"
	"os"
	"testing"
)

// TestS3Contract runs the shared contract suite against a real S3-compatible
// endpoint. It is gated behind MINIO_ENDPOINT so the default `go test` run
// needs no external service; CI spins up a MinIO container and sets it.
//
//	MINIO_ENDPOINT=localhost:9000 MINIO_ACCESS_KEY=minioadmin \
//	MINIO_SECRET_KEY=minioadmin MINIO_BUCKET=test go test ./internal/storage
func TestS3Contract(t *testing.T) {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	if endpoint == "" {
		t.Skip("MINIO_ENDPOINT not set; skipping S3 contract test (run in CI with MinIO)")
	}
	cfg := S3Config{
		Endpoint:  endpoint,
		Bucket:    os.Getenv("MINIO_BUCKET"),
		AccessKey: os.Getenv("MINIO_ACCESS_KEY"),
		SecretKey: os.Getenv("MINIO_SECRET_KEY"),
		Region:    "us-east-1",
		Secure:    false,
	}
	if cfg.Bucket == "" {
		cfg.Bucket = "test"
	}
	if cfg.AccessKey == "" {
		cfg.AccessKey = "minioadmin"
	}
	if cfg.SecretKey == "" {
		cfg.SecretKey = "minioadmin"
	}

	RunContractTests(t, func() Backend {
		s, err := NewS3(context.Background(), &cfg)
		if err != nil {
			t.Fatalf("NewS3: %v", err)
		}
		return s
	})
}
