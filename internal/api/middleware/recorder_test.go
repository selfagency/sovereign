package middleware

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestResponseRecorderFlush verifies Flush delegates to an underlying
// http.Flusher and is a no-op when the writer does not support flushing.
func TestResponseRecorderFlush(t *testing.T) {
	// httptest.ResponseRecorder implements http.Flusher.
	base := httptest.NewRecorder()
	rec := newResponseRecorder(base)
	rec.Flush() // must not panic; delegated to base

	// A writer that does NOT implement http.Flusher: Flush must be a no-op.
	dumb := &dumbResponseWriter{}
	rec2 := newResponseRecorder(dumb)
	rec2.Flush() // must not panic
}

// TestResponseRecorderHijack verifies Hijack delegates to an underlying
// http.Hijacker and returns ErrNotSupported otherwise.
func TestResponseRecorderHijack(t *testing.T) {
	// A writer that DOES implement http.Hijacker.
	hj := &hijackResponseWriter{base: httptest.NewRecorder()}
	rec := newResponseRecorder(hj)
	conn, rw, err := rec.Hijack()
	if err != nil {
		t.Fatalf("Hijack on supported writer: %v", err)
	}
	if conn == nil || rw == nil {
		t.Fatalf("Hijack returned nil conn/rw: %v %v", conn, rw)
	}

	// A writer that does NOT implement http.Hijacker.
	dumb := &dumbResponseWriter{}
	rec2 := newResponseRecorder(dumb)
	if _, _, err := rec2.Hijack(); err != http.ErrNotSupported {
		t.Fatalf("Hijack on unsupported writer err = %v, want ErrNotSupported", err)
	}
}

// hijackResponseWriter wraps an httptest.ResponseRecorder and implements
// http.Hijacker so the delegate path can be exercised.
type hijackResponseWriter struct {
	base *httptest.ResponseRecorder
}

func (h *hijackResponseWriter) Header() http.Header { return h.base.Header() }
func (h *hijackResponseWriter) WriteHeader(c int)   { h.base.WriteHeader(c) }
func (h *hijackResponseWriter) Write(b []byte) (int, error) {
	return h.base.Write(b)
}

func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, _ := net.Pipe()
	return conn, bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), nil
}

// dumbResponseWriter implements http.ResponseWriter but neither http.Flusher
// nor http.Hijacker.
type dumbResponseWriter struct {
	header http.Header
}

func (d *dumbResponseWriter) Header() http.Header {
	if d.header == nil {
		d.header = make(http.Header)
	}
	return d.header
}

func (d *dumbResponseWriter) WriteHeader(int) {}

func (d *dumbResponseWriter) Write(b []byte) (int, error) { return len(b), nil }

var _ http.ResponseWriter = (*dumbResponseWriter)(nil)
