package middleware

import (
	"bufio"
	"net"
	"net/http"
)

// responseRecorder wraps http.ResponseWriter to capture the status code and
// byte count for the access log and the conditional/idempotency middlewares.
// It implements http.Flusher and http.Hijacker so downstream handlers that
// rely on streaming or websockets keep working. Panics during the wrapped
// handler are left to the Recover middleware, not swallowed here.
type responseRecorder struct {
	http.ResponseWriter
	status int // 0 until WriteHeader; Write defaults to 200
	bytes  int
	wrote  bool // true once the handler wrote a status or body
}

// newResponseRecorder wraps w with an initial default status of 200 so a
// handler that writes a body without an explicit WriteHeader logs 200.
func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader records the status code before delegating.
func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

// Write records the byte count before delegating.
func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	r.wrote = true
	return n, err
}

// Flush implements http.Flusher.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

var (
	_ http.Flusher  = (*responseRecorder)(nil)
	_ http.Hijacker = (*responseRecorder)(nil)
)
