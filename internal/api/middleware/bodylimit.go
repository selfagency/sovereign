package middleware

import (
	"errors"
	"io"
	"net/http"

	"github.com/selfagency/sovereign/internal/api/problem"
)

// DefaultMaxBodyBytes is the default request-body limit for JSON payloads
// (64 KiB). Routes can raise or lower it in later phases via the route table.
const DefaultMaxBodyBytes = 64 * 1024

// BodyLimit caps the request body at maxBytes using http.MaxBytesReader. A
// body exceeding the limit surfaces a 413 problem+json response: the reader
// records the overflow, and if the handler did not already write a response,
// the middleware drains the body and writes 413. A nil/zero limit disables the
// check.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxBytes <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			rec := newResponseRecorder(w)
			body := &maxBytesReader{src: http.MaxBytesReader(rec, r.Body, maxBytes)}
			r.Body = body
			next.ServeHTTP(rec, r)

			// Drain any unread body to surface a MaxBytesError the handler
			// may have missed, then reject if nothing was written yet.
			if !rec.wrote {
				if _, err := io.Copy(io.Discard, r.Body); err != nil && body.overLimit() {
					writePayloadTooLarge(rec)
					return
				}
			}
		})
	}
}

// maxBytesReader records whether the underlying MaxBytesReader rejected the
// body, so the middleware can distinguish an oversize body from other errors.
type maxBytesReader struct {
	src      io.ReadCloser
	exceeded bool
}

func (m *maxBytesReader) Read(p []byte) (int, error) {
	n, err := m.src.Read(p)
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		m.exceeded = true
	}
	return n, err
}

func (m *maxBytesReader) Close() error { return m.src.Close() }

// overLimit reports whether the body exceeded the configured limit.
func (m *maxBytesReader) overLimit() bool { return m.exceeded }

// writePayloadTooLarge writes the 413 problem to w.
func writePayloadTooLarge(w http.ResponseWriter) {
	problem.PayloadTooLarge().Write(w)
}
