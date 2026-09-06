package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// Conditional implements conditional-request handling for GET responses. For
// Phase 1 this is intentionally light: on GET it buffers the response, sets an
// ETag derived from the response body, and returns 304 when If-None-Match
// matches (stripping the body). There is no mandatory If-Match (428/412)
// handling — that precondition was dropped (C3).
type Conditional struct{}

// Middleware returns the conditional-request handler.
func (c *Conditional) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		buf := &bytes.Buffer{}
		rec := newResponseRecorder(&bufferWriter{w: w, buf: buf})
		next.ServeHTTP(rec, r)

		// Only successful GET responses get an ETag.
		if rec.status >= 200 && rec.status < 300 && rec.Header().Get("ETag") == "" {
			tag := etagOf(buf.Bytes())
			rec.Header().Set("ETag", tag)
			if etagMatch(r.Header.Get("If-None-Match"), tag) {
				// 304 carries no body: set the ETag on the real writer.
				w.Header().Set("ETag", tag)
				w.Header().Del("Content-Length")
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		// Otherwise flush the buffered body to the real writer. Headers were
		// already written through to w (bufferWriter.Header forwards to w).
		w.WriteHeader(rec.status)
		_, _ = w.Write(buf.Bytes())
	})
}

// bufferWriter captures the response status and body so the middleware can
// decide whether to serve the full response or a 304. Headers are written to
// the underlying writer immediately; the status and body are held back.
type bufferWriter struct {
	w      http.ResponseWriter
	buf    *bytes.Buffer
	status int
}

func (b *bufferWriter) Header() http.Header  { return b.w.Header() }
func (b *bufferWriter) WriteHeader(code int) { b.status = code }
func (b *bufferWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.buf.Write(p)
}

// copyHeaders copies all headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// etagOf derives a strong ETag from the SHA-256 of the response body. A
// zero-length body falls back to a hash of an empty marker so the ETag stays
// stable across identical empty responses.
func etagOf(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// etagMatch reports whether an If-None-Match header matches tag. Wildcard "*"
// matches any; otherwise the tags are compared exactly (no weak-prefix handling
// in Phase 1).
func etagMatch(header, tag string) bool {
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for _, part := range splitETags(header) {
		if part == tag {
			return true
		}
	}
	return false
}

// splitETags splits a comma-separated If-None-Match value into trimmed tags.
func splitETags(header string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(header); i++ {
		if i == len(header) || header[i] == ',' {
			if t := trimSpace(header[start:i]); t != "" {
				out = append(out, t)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
