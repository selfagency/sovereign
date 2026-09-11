package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// defaultS3DialTimeout bounds the constructor's network probes when
// DialTimeout is unset.
const defaultS3DialTimeout = 30 * time.Second

// S3 is a Backend backed by any S3-compatible endpoint (AWS S3, MinIO,
// Backblaze B2, etc.) via minio-go.
type S3 struct {
	client  *minio.Client
	bucket  string
	maxSize int64
}

// S3Config holds connection settings for an S3-compatible endpoint.
type S3Config struct {
	Endpoint  string // e.g. "s3.amazonaws.com" or "localhost:9000"
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string
	Secure    bool // https when true
	// CreateBucket makes NewS3 create the bucket when it does not exist.
	// Default (false) fails closed: the operator must provision the bucket.
	CreateBucket bool
	// DialTimeout bounds the constructor's network probes. 0 uses a 30s
	// default.
	DialTimeout time.Duration
	// MaxSize caps a single Put body in bytes (0 = unlimited). Bodies larger
	// than the cap are rejected mid-upload instead of being buffered whole.
	MaxSize int64
}

// NewS3 builds an S3 backend. ctx bounds the constructor's network probes
// (bucket existence check and, when CreateBucket is set, creation); a
// zero-value DialTimeout applies a 30s default. Bucket creation is opt-in
// (D4): the constructor never provisions storage unless asked.
func NewS3(ctx context.Context, cfg *S3Config) (*S3, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.Secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, err
	}
	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = defaultS3DialTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	exists, err := client.BucketExists(probeCtx, cfg.Bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if !cfg.CreateBucket {
			return nil, errors.New("storage: s3 bucket " + cfg.Bucket + " does not exist (set storage.s3.create_bucket to create it)")
		}
		if err := client.MakeBucket(probeCtx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, err
		}
	}
	return &S3{client: client, bucket: cfg.Bucket, maxSize: maxObjectSize(cfg)}, nil
}

// maxObjectSize resolves the effective per-object cap (0 = unlimited).
func maxObjectSize(cfg *S3Config) int64 {
	return cfg.MaxSize
}

// Put stores r under key in the S3 bucket. The body streams to S3 (no
// io.ReadAll): minio-go multipart-uploads unknown-size readers, bounding
// memory to its part size. Bodies larger than MaxSize (when set) are
// rejected mid-upload (D3).
func (s *S3) Put(ctx context.Context, key string, r io.Reader, contentType string) (Blob, error) {
	body := io.Reader(r)
	if s.maxSize > 0 {
		body = http.MaxBytesReader(nil, io.NopCloser(r), s.maxSize)
	}
	info, err := s.client.PutObject(ctx, s.bucket, key, body, -1, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		if isBodyTooLarge(err) {
			return Blob{}, errors.New("storage: request body too large")
		}
		return Blob{}, err
	}
	return Blob{Key: key, ContentType: contentType, Size: info.Size}, nil
}

// isBodyTooLarge reports whether err is http.MaxBytesReader's limit error.
func isBodyTooLarge(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge) || strings.Contains(err.Error(), "request body too large")
}

// Get returns the stored object for key.
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, Blob, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, Blob{}, err
	}
	st, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		if isNotFound(err) {
			return nil, Blob{}, ErrNotFound
		}
		return nil, Blob{}, err
	}
	return obj, Blob{Key: key, ContentType: st.ContentType, Size: st.Size}, nil
}

// Delete removes the stored object for key. It returns ErrNotFound if the
// key does not exist, matching the FS backend contract.
func (s *S3) Delete(ctx context.Context, key string) error {
	err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// List returns all stored objects under prefix.
func (s *S3) List(ctx context.Context, prefix string) ([]Blob, error) {
	var out []Blob
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		out = append(out, Blob{Key: obj.Key, ContentType: obj.ContentType, Size: obj.Size})
	}
	return out, nil
}

func isNotFound(err error) bool {
	var resp minio.ErrorResponse
	return errors.As(err, &resp) && resp.Code == "NoSuchKey" ||
		strings.Contains(err.Error(), "NoSuchKey")
}

var _ Backend = (*S3)(nil)
