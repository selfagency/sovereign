package storage

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// mockS3Server is a minimal S3-compatible server for testing the S3 backend
// without a live MinIO. It implements the subset of the S3 API that minio-go
// uses for the operations the backend needs: bucket existence, multipart
// upload (put), get, delete, list.
func mockS3Server(t *testing.T) *httptest.Server {
	t.Helper()
	// bucket -> key -> content
	buckets := map[string]map[string][]byte{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		parts := splitPath(r.URL.Path)
		if len(parts) < 1 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		bucket := parts[0]
		key := ""
		if len(parts) > 1 {
			key = joinPath(parts[1:])
		}

		switch r.Method {
		case http.MethodHead:
			// BucketExists (key empty) or object stat (key set).
			if key == "" {
				if _, ok := buckets[bucket]; ok {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
				return
			}
			if content, ok := buckets[bucket][key]; ok {
				w.Header().Set("Last-Modified", "Mon, 2 Jan 2006 15:04:05 GMT")
				w.Header().Set("Content-Length", strconv.Itoa(len(content)))
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		case http.MethodPut:
			if key == "" {
				// MakeBucket
				buckets[bucket] = map[string][]byte{}
				w.WriteHeader(http.StatusOK)
				return
			}
			body, _ := io.ReadAll(r.Body)
			if buckets[bucket] == nil {
				buckets[bucket] = map[string][]byte{}
			}
			if r.URL.Query().Get("partNumber") != "" {
				// Multipart part upload: store decoded content, return ETag.
				buckets[bucket][key] = decodeChunked(body)
				w.Header().Set("ETag", `"etag-1"`)
				w.WriteHeader(http.StatusOK)
				return
			}
			// minio-go may send aws-chunked encoding; decode it to store the
			// actual object content.
			buckets[bucket][key] = decodeChunked(body)
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			// Multipart upload initiation: POST /bucket/key?uploads (bare
			// query param, no value).
			if r.URL.Query().Has("uploads") {
				w.Header().Set("Content-Type", "application/xml")
				w.Write([]byte(`<?xml version="1.0"?><InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`))
				return
			}
			// Complete multipart upload: POST /bucket/key?uploadId=...
			// Content was already stored during the part upload; just confirm.
			if r.URL.Query().Has("uploadId") {
				w.Header().Set("Content-Type", "application/xml")
				// minio-go requires Bucket to be populated; an empty Bucket
				// makes it re-parse the body as an error response.
				w.Write([]byte(`<?xml version="1.0"?><CompleteMultipartUploadResult><Bucket>` + bucket + `</Bucket><Key>` + key + `</Key><ETag>"etag-complete"</ETag></CompleteMultipartUploadResult>`))
				return
			}
			http.Error(w, "unsupported post", http.StatusBadRequest)
		case http.MethodGet:
			if key == "" {
				// ListObjects
				w.Header().Set("Content-Type", "application/xml")
				w.Write([]byte(listObjectsXML(buckets[bucket])))
				return
			}
			content, ok := buckets[bucket][key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`<?xml version="1.0"?><Error><Code>NoSuchKey</Code></Error>`))
				return
			}
			w.Header().Set("Last-Modified", "Mon, 2 Jan 2006 15:04:05 GMT")
			w.Write(content)
		case http.MethodDelete:
			if _, ok := buckets[bucket][key]; !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`<?xml version="1.0"?><Error><Code>NoSuchKey</Code></Error>`))
				return
			}
			delete(buckets[bucket], key)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mux)
}

// decodeChunked strips aws-chunked framing from a body. Format per chunk: Format per chunk:
// "<hex-size>;chunk-signature=...\r\n<data>\r\n", terminated by a 0-size chunk.
func decodeChunked(body []byte) []byte {
	var out []byte
	rest := body
	for len(rest) > 0 {
		// Find the CRLF after the size line.
		crlf := bytes.Index(rest, []byte("\r\n"))
		if crlf < 0 {
			break
		}
		sizeLine := string(rest[:crlf])
		rest = rest[crlf+2:]
		// Size is hex before any ';' (chunk-signature suffix).
		semi := strings.Index(sizeLine, ";")
		if semi >= 0 {
			sizeLine = sizeLine[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil || size <= 0 {
			break
		}
		if int64(len(rest)) < size {
			break
		}
		out = append(out, rest[:size]...)
		rest = rest[size:]
		// Skip the trailing CRLF after chunk data.
		if len(rest) >= 2 && rest[0] == '\r' && rest[1] == '\n' {
			rest = rest[2:]
		}
	}
	return out
}

func splitPath(p string) []string {
	var out []string
	cur := ""
	for _, c := range p {
		if c == '/' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func joinPath(parts []string) string {
	return strings.Join(parts, "/")
}

func listObjectsXML(objs map[string][]byte) string {
	out := `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`
	for k := range objs {
		out += `<Contents><Key>` + k + `</Key><Size>0</Size></Contents>`
	}
	out += `</ListBucketResult>`
	return out
}

// TestS3BackendAgainstMock runs the S3 backend against a mock server.
func TestS3BackendAgainstMock(t *testing.T) {
	srv := mockS3Server(t)
	defer srv.Close()

	cfg := S3Config{
		Endpoint:  srv.URL[7:], // strip http://
		Bucket:    "test",
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Region: "us-east-1", Secure: false,
		CreateBucket: true,
	}
	s, err := NewS3(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	ctx := context.Background()

	// Put
	blob, err := s.Put(ctx, "a/b.txt", bytes.NewReader([]byte("hello")), "text/plain")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if blob.Key != "a/b.txt" {
		t.Fatalf("blob key = %s", blob.Key)
	}

	// Get
	rc, got, err := s.Get(ctx, "a/b.txt")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	if string(body) != "hello" {
		t.Fatalf("got %q, want hello", body)
	}
	if got.Key != "a/b.txt" {
		t.Fatalf("got key = %s", got.Key)
	}

	// Get missing
	if _, _, err := s.Get(ctx, "missing"); err == nil {
		t.Fatal("expected error for missing key")
	}

	// List
	blobs, err := s.List(ctx, "a/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(blobs) != 1 || blobs[0].Key != "a/b.txt" {
		t.Fatalf("list = %v", blobs)
	}

	// Delete
	if err := s.Delete(ctx, "a/b.txt"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := s.Get(ctx, "a/b.txt"); err == nil {
		t.Fatal("expected error after delete")
	}
}

var _ = xml.Marshal // keep xml import if unused
