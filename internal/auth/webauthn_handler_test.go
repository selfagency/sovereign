package auth

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// TestSessionStorePutGet verifies put/get round-trip.
func TestSessionStorePutGet(t *testing.T) {
	s := NewSessionStore(time.Minute)
	s.Put("ch1", &webauthn.SessionData{Challenge: "ch1"})
	got, ok := s.Get("ch1")
	if !ok || got.Challenge != "ch1" {
		t.Fatalf("get = %v, %v", got, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("unknown challenge returned")
	}
}

// TestSessionStoreExpiry verifies expired sessions are evicted.
func TestSessionStoreExpiry(t *testing.T) {
	s := NewSessionStore(-time.Second) // already expired
	s.Put("ch1", &webauthn.SessionData{Challenge: "ch1"})
	if _, ok := s.Get("ch1"); ok {
		t.Fatal("expired session returned")
	}
}

// TestSessionStoreDelete verifies Delete removes a session.
func TestSessionStoreDelete(t *testing.T) {
	s := NewSessionStore(time.Minute)
	s.Put("ch1", &webauthn.SessionData{Challenge: "ch1"})
	s.Delete("ch1")
	if _, ok := s.Get("ch1"); ok {
		t.Fatal("deleted session still present")
	}
}

// TestSessionStoreEvictsOldestWhenFull verifies that once a store exceeds its
// capacity cap the oldest entry is evicted, bounding unbounded growth from
// never-completed challenges.
func TestSessionStoreEvictsOldestWhenFull(t *testing.T) {
	s := NewSessionStoreWithMax(time.Minute, 2)
	s.Put("a", &webauthn.SessionData{Challenge: "a"})
	s.Put("b", &webauthn.SessionData{Challenge: "b"})
	s.Put("c", &webauthn.SessionData{Challenge: "c"})

	if _, ok := s.Get("a"); ok {
		t.Fatal("oldest entry not evicted when over capacity")
	}
	if _, ok := s.Get("b"); !ok {
		t.Fatal("second entry evicted unexpectedly")
	}
	if _, ok := s.Get("c"); !ok {
		t.Fatal("newest entry evicted unexpectedly")
	}
}

// TestSessionStoreZeroMaxIsUnbounded verifies a zero max (constructor default
// path) keeps entries without eviction.
func TestSessionStoreZeroMaxIsUnbounded(t *testing.T) {
	s := NewSessionStoreWithMax(time.Minute, 0)
	s.Put("a", &webauthn.SessionData{Challenge: "a"})
	s.Put("b", &webauthn.SessionData{Challenge: "b"})
	if _, ok := s.Get("a"); !ok {
		t.Fatal("entry evicted with zero cap")
	}
	if _, ok := s.Get("b"); !ok {
		t.Fatal("entry evicted with zero cap")
	}
}
