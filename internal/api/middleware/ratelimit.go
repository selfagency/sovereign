package middleware

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/selfagency/sovereign/internal/api/problem"
)

// tokenBucket is a simple per-IP rate limiter: it refills tokens at a fixed
// rate up to a burst capacity. It is not safe for concurrent use by itself;
// RateLimiter serializes access with a mutex.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// RateLimiter enforces a per-IP token-bucket rate limit. It keys clients by
// their source IP (from RemoteAddr) and rejects requests that exhaust the
// bucket with a 429 problem, Retry-After, and RateLimit-* headers. Idle
// buckets are pruned by a background goroutine so the map cannot grow without
// bound under address churn.
type RateLimiter struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	burst    int
	buckets  map[string]*tokenBucket
	lastSeen map[string]time.Time
	stop     chan struct{}
	once     sync.Once
	now      func() time.Time // test hook; defaults to time.Now
}

// NewRateLimiter returns a RateLimiter that allows burst tokens up front and
// refills at rate tokens/second per source IP. close is a helper to stop the
// background pruner; the returned func is also exposed as (r *RateLimiter) Close.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	r := &RateLimiter{
		rate:     rate,
		burst:    burst,
		buckets:  make(map[string]*tokenBucket),
		lastSeen: make(map[string]time.Time),
		stop:     make(chan struct{}),
		now:      time.Now,
	}
	go r.pruneLoop()
	return r
}

// Close stops the background pruner goroutine.
func (r *RateLimiter) Close() { r.once.Do(func() { close(r.stop) }) }

// Middleware returns a handler enforcing the per-IP rate limit.
func (r *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ip := clientIP(req)
		now := r.now()
		if !r.allow(ip, now) {
			retryAfter := r.retryAfter(ip)
			w.Header().Set("RateLimit-Limit", strconv.Itoa(r.burst))
			w.Header().Set("RateLimit-Remaining", "0")
			w.Header().Set("RateLimit-Reset", strconv.FormatInt(now.Add(retryAfter).Unix(), 10))
			problem.RateLimited(retryAfter).Write(w)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// allow consumes one token for ip, refilling the bucket first. It returns
// false when the bucket is empty.
func (r *RateLimiter) allow(ip string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[ip]
	if !ok {
		b = &tokenBucket{tokens: float64(r.burst), last: now}
		r.buckets[ip] = b
	}
	r.lastSeen[ip] = now
	// Refill: add elapsed*rate tokens, capped at burst.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * r.rate
	if b.tokens > float64(r.burst) {
		b.tokens = float64(r.burst)
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// retryAfter estimates the seconds until the caller's bucket refills one token.
func (r *RateLimiter) retryAfter(ip string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rate <= 0 {
		return time.Second
	}
	if b, ok := r.buckets[ip]; ok {
		missing := 1 - b.tokens
		if missing > 0 {
			return time.Duration(missing / r.rate * float64(time.Second))
		}
	}
	return 0
}

// pruneLoop periodically drops buckets that have been idle for a full window
// (10x the burst refill time), bounding map growth under address churn.
func (r *RateLimiter) pruneLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.prune(time.Now())
		}
	}
}

func (r *RateLimiter) prune(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A bucket idle for this long is unreachable churn. Tune via the refill
	// window: keep buckets roughly as long as their full burst would refill.
	ttl := time.Duration(float64(r.burst)/r.rate*float64(time.Second)) * 10
	if ttl < time.Minute {
		ttl = time.Minute
	}
	for ip, last := range r.lastSeen {
		if now.Sub(last) > ttl {
			delete(r.buckets, ip)
			delete(r.lastSeen, ip)
		}
	}
}

// clientIP returns the source IP from RemoteAddr, stripping the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
