package middleware

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/selfagency/sovereign/internal/api/problem"
)

// Timeout enforces a per-route deadline. getTimeout returns the timeout budget
// for the current request (0 or negative disables the timeout). A handler that
// exceeds its budget is aborted with an RFC 9457 problem+json 503 (audit D4:
// the contract must be consistent with the rest of the control plane, not a
// plain-text body) while the server keeps serving other requests. The handler
// runs in a goroutine so a handler that ignores its context is still aborted;
// the response is buffered and only committed if the handler finishes in time.
//
// The route table drives this: NewHandler supplies a getTimeout that returns
// the route's Timeout column, or 0 for routes marked LongRunning (Phase 3
// backup run/restore), so slow long-running handlers are never killed by the
// default timeout.
func Timeout(getTimeout func(*http.Request) time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d := getTimeout(r)
			if d <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()

			buf := &bytes.Buffer{}
			tw := &timeoutWriter{header: w.Header(), buf: buf}
			done := make(chan struct{})
			go func() {
				next.ServeHTTP(tw, r.WithContext(ctx))
				close(done)
			}()

			select {
			case <-done:
				// Handler finished in time: commit the buffered response.
				if tw.status == 0 {
					tw.status = http.StatusOK
				}
				w.WriteHeader(tw.status)
				_, _ = w.Write(buf.Bytes())
			case <-ctx.Done():
				// Deadline exceeded: abort with a problem+json 503. The handler
				// goroutine may still be running; it writes to the buffer, which
				// is discarded.
				problem.ServiceUnavailable().Write(w)
			}
		})
	}
}

// timeoutWriter buffers the handler's response so a timed-out handler's
// partial output is never committed. Headers are written to the real writer
// immediately (so downstream middleware sees them); status and body are held
// back until the handler completes within the deadline.
type timeoutWriter struct {
	header http.Header
	buf    *bytes.Buffer
	status int
}

func (t *timeoutWriter) Header() http.Header  { return t.header }
func (t *timeoutWriter) WriteHeader(code int) { t.status = code }
func (t *timeoutWriter) Write(p []byte) (int, error) {
	if t.status == 0 {
		t.status = http.StatusOK
	}
	return t.buf.Write(p)
}
