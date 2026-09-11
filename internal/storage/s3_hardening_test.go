package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// unknownSizeReader reports no length (io.Reader only), forcing the S3
// streaming (multipart) path.
type unknownSizeReader struct{ data []byte }

func (u *unknownSizeReader) Read(p []byte) (int, error) {
	if len(u.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, u.data)
	u.data = u.data[n:]
	return n, nil
}

// TestS3PutStreamsUnknownSize verifies Put accepts a reader of unknown size
// (no io.ReadAll: the body streams to S3, memory bounded by the part size).
func TestS3PutStreamsUnknownSize(t *testing.T) {
	srv := mockS3Server(t)
	defer srv.Close()

	s, err := NewS3(context.Background(), &S3Config{
		Endpoint: srv.URL[7:], Bucket: "test",
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Region: "us-east-1", Secure: false,
		CreateBucket: true,
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	blob, err := s.Put(context.Background(), "stream/x.bin", &unknownSizeReader{data: []byte("streamed-body")}, "application/octet-stream")
	if err != nil {
		t.Fatalf("Put unknown size: %v", err)
	}
	if blob.Key != "stream/x.bin" {
		t.Fatalf("blob key = %q, want stream/x.bin", blob.Key)
	}
	// Round-trip.
	rc, got, err := s.Get(context.Background(), "stream/x.bin")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != "streamed-body" {
		t.Fatalf("round-tripped body = %q, want %q", b, "streamed-body")
	}
	if got.ContentType != "application/octet-stream" {
		t.Fatalf("content type = %q, want application/octet-stream", got.ContentType)
	}
}

// TestS3PutRejectsOversized verifies a body exceeding MaxSize is rejected
// rather than buffered whole (D3).
func TestS3PutRejectsOversized(t *testing.T) {
	srv := mockS3Server(t)
	defer srv.Close()

	s, err := NewS3(context.Background(), &S3Config{
		Endpoint: srv.URL[7:], Bucket: "test",
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Region: "us-east-1", Secure: false,
		CreateBucket: true,
		MaxSize:      8,
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	_, err = s.Put(context.Background(), "big.bin", strings.NewReader("0123456789abcdef"), "application/octet-stream")
	if err == nil {
		t.Fatal("Put oversized body succeeded, want error")
	}
	if !strings.Contains(err.Error(), "too large") && !strings.Contains(err.Error(), "body") {
		t.Fatalf("oversized error = %v, want body-size rejection", err)
	}
}

// TestS3ConstructorTimeout verifies NewS3 honors its dial timeout against a
// hanging endpoint instead of blocking forever (D4).
func TestS3ConstructorTimeout(t *testing.T) {
	// A handler that sleeps longer than the configured dial timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := NewS3(context.Background(), &S3Config{
		Endpoint: srv.URL[7:], Bucket: "test",
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Region: "us-east-1", Secure: false,
		DialTimeout: 200 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("NewS3 against hanging endpoint succeeded, want timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("NewS3 blocked %v, want dial timeout at ~200ms", elapsed)
	}
}

// TestS3BucketCreationOptIn verifies bucket creation is opt-in (D4): with
// CreateBucket=false a missing bucket is an error; with true it is created.
func TestS3BucketCreationOptIn(t *testing.T) {
	srv := mockS3Server(t)
	defer srv.Close()

	// Opt-in disabled: missing bucket is an error (fail-closed).
	_, err := NewS3(context.Background(), &S3Config{
		Endpoint: srv.URL[7:], Bucket: "missing",
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Region: "us-east-1", Secure: false,
	})
	if err == nil {
		t.Fatal("NewS3 with missing bucket and CreateBucket=false succeeded, want error")
	}

	// Opt-in enabled: the bucket is created.
	s, err := NewS3(context.Background(), &S3Config{
		Endpoint: srv.URL[7:], Bucket: "created",
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Region: "us-east-1", Secure: false,
		CreateBucket: true,
	})
	if err != nil {
		t.Fatalf("NewS3 with CreateBucket=true: %v", err)
	}
	if _, err := s.Put(context.Background(), "k", strings.NewReader("v"), "text/plain"); err != nil {
		t.Fatalf("Put into freshly created bucket: %v", err)
	}
}

// TestS3PutContextCanceled verifies a canceled context aborts the upload.
func TestS3PutContextCanceled(t *testing.T) {
	srv := mockS3Server(t)
	defer srv.Close()

	s, err := NewS3(context.Background(), &S3Config{
		Endpoint: srv.URL[7:], Bucket: "test",
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Region: "us-east-1", Secure: false,
		CreateBucket: true,
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Put(ctx, "canceled.bin", &unknownSizeReader{data: []byte("x")}, "text/plain")
	if err == nil {
		t.Fatal("Put with canceled context succeeded, want error")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err = %v, want context canceled", err)
	}
}
