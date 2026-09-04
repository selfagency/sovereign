package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/selfagency/sovereign/internal/api/problem"
)

// idempotencyKeyHeader is the client-supplied key that makes a POST replayable.
const idempotencyKeyHeader = "Idempotency-Key"

// idempotencyRetention is how long a stored idempotency result is kept before
// it can be reused. Phase 1 uses an in-memory TTL map; persistence (the store's
// idempotency_keys table) is wired in Phase 3.
const idempotencyRetention = 24 * time.Hour

// storedResponse is a replayable idempotency result.
type storedResponse struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"`
	expires time.Time
}

// Idempotency makes declared POST routes idempotent: it reads an
// Idempotency-Key header, hashes it with the request, and stores the response.
// A replay with the same key returns the original response (up to the
// retention window) instead of re-executing the handler. Missing key on a
// declared route → 400. In-memory TTL map for Phase 1; persistence is Phase 3.
type Idempotency struct {
	mu    sync.Mutex
	store map[string]*storedResponse
	stop  chan struct{}
	once  sync.Once
	now   func() time.Time // test hook
	// RequireKey reports whether the route requires an Idempotency-Key.
	RequireKey func(path string) bool
}

// NewIdempotency returns an Idempotency middleware with a live retention
// pruner. Call Close to stop the pruner.
func NewIdempotency(requireKey func(path string) bool) *Idempotency {
	id := &Idempotency{
		store:      make(map[string]*storedResponse),
		stop:       make(chan struct{}),
		now:        time.Now,
		RequireKey: requireKey,
	}
	go id.pruneLoop()
	return id
}

// Close stops the background retention pruner.
func (id *Idempotency) Close() { id.once.Do(func() { close(id.stop) }) }

// Middleware returns the idempotency handler.
func (id *Idempotency) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || id.RequireKey == nil || !id.RequireKey(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		key := r.Header.Get(idempotencyKeyHeader)
		if key == "" {
			problem.InvalidRequest("missing required " + idempotencyKeyHeader + " header").Write(w)
			return
		}

		hash := idempotencyHash(key, r)
		if stored := id.lookup(hash); stored != nil {
			replay(w, stored)
			return
		}

		buf := &bytes.Buffer{}
		rec := newResponseRecorder(&bufferWriter{w: w, buf: buf})
		next.ServeHTTP(rec, r)

		stored := &storedResponse{
			Status:  rec.status,
			Headers: rec.Header().Clone(),
			Body:    buf.Bytes(),
			expires: id.now().Add(idempotencyRetention),
		}
		id.record(hash, stored)

		copyHeaders(w.Header(), rec.Header())
		w.WriteHeader(rec.status)
		_, _ = w.Write(buf.Bytes())
	})
}

// lookup returns a non-expired stored response for hash, or nil.
func (id *Idempotency) lookup(hash string) *storedResponse {
	id.mu.Lock()
	defer id.mu.Unlock()
	stored, ok := id.store[hash]
	if !ok {
		return nil
	}
	if id.now().After(stored.expires) {
		delete(id.store, hash)
		return nil
	}
	return stored
}

// record stores a response under hash, dropping any prior entry.
func (id *Idempotency) record(hash string, s *storedResponse) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.store[hash] = s
}

// replay writes a stored response back to w.
func replay(w http.ResponseWriter, s *storedResponse) {
	copyHeaders(w.Header(), s.Headers)
	w.WriteHeader(s.Status)
	_, _ = w.Write(s.Body)
}

// idempotencyHash binds the key to the request so the same key on a different
// request is not confused. It hashes key + method + path + body. The body is
// restored after reading so downstream handlers can still consume it.
func idempotencyHash(key string, r *http.Request) string {
	var body []byte
	if r.Body != nil {
		body, _ = readAll(r.Body)
		// Restore the body for the real handler (idempotency only peeks).
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	h := sha256.New()
	h.Write([]byte(key))
	h.Write([]byte(r.Method))
	h.Write([]byte(r.URL.Path))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// pruneLoop drops expired entries on a timer.
func (id *Idempotency) pruneLoop() {
	ticker := time.NewTicker(idempotencyRetention / 2)
	defer ticker.Stop()
	for {
		select {
		case <-id.stop:
			return
		case now := <-ticker.C:
			id.prune(now)
		}
	}
}

func (id *Idempotency) prune(now time.Time) {
	id.mu.Lock()
	defer id.mu.Unlock()
	for k, s := range id.store {
		if now.After(s.expires) {
			delete(id.store, k)
		}
	}
}

// readAll reads a request body without a limit (the BodyLimit middleware has
// already capped it). It is used only to fingerprint the request.
func readAll(body interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := body.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			return buf.Bytes(), nil // io.EOF and real errors both stop the read
		}
	}
}
