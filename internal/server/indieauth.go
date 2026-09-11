package server

import (
	"context"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"go.hacdias.com/indielib/indieauth"

	"github.com/selfagency/sovereign/internal/auth"
	ia "github.com/selfagency/sovereign/internal/protocols/indieauth"
)

// indieauthIssuer adapts the auth package's token minting to the IndieAuth
// TokenIssuer interface.
type indieauthIssuer struct {
	key      *rsa.PrivateKey
	issuer   string
	audience string
}

// internalError logs the real error server-side and returns a stable, generic
// message to the client. Raw internal errors must never reach the response
// body (security audit B1).
func internalError(w http.ResponseWriter, op string, err error) {
	slog.Error(op, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// IssueForProfile mints an access token for an IndieAuth identity URL.
func (i *indieauthIssuer) IssueForProfile(ctx context.Context, profileURL string, scopes []string) (string, error) {
	return auth.IssueForProfile(i.key, profileURL, scopes, i.issuer, i.audience)
}

// indieAuthSessionStore persists authorization requests between the authorize
// and token steps, keyed by state, with a TTL.
type indieAuthSessionStore struct {
	mu   sync.Mutex
	data map[string]indieAuthSessionEntry
}

type indieAuthSessionEntry struct {
	req       *indieauth.AuthenticationRequest
	expiresAt time.Time
}

func newIndieAuthSessionStore() *indieAuthSessionStore {
	return &indieAuthSessionStore{data: map[string]indieAuthSessionEntry{}}
}

func (s *indieAuthSessionStore) put(state string, req *indieauth.AuthenticationRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = indieAuthSessionEntry{req: req, expiresAt: time.Now().Add(5 * time.Minute)}
}

func (s *indieAuthSessionStore) get(state string) (*indieauth.AuthenticationRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[state]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(s.data, state)
		return nil, false
	}
	return e.req, true
}

// indieAuthAuthorize handles the IndieAuth authorization endpoint. It parses
// the authorization request, stores it by state, and redirects back with a
// code.
func indieAuthAuthorize(b *ia.Bridge, sessions *indieAuthSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authReq, err := b.ParseAuthorization(r)
		if err != nil {
			slog.Error("indieauth: parse authorization", "err", err)
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
			return
		}
		sessions.put(authReq.State, authReq)
		// Auto-approve first-party: the identity host is the only client.
		redirect := authReq.RedirectURI + "?code=" + authReq.State
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

// indieAuthToken handles the IndieAuth token endpoint. It validates the token
// exchange against the stored authorization request and mints an access token.
func indieAuthToken(b *ia.Bridge, sessions *indieAuthSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			slog.Error("indieauth: parse form", "err", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		state := r.FormValue("code")
		authReq, ok := sessions.get(state)
		if !ok {
			http.Error(w, "unknown or expired authorization code", http.StatusBadRequest)
			return
		}
		if err := b.ValidateTokenExchange(authReq, r); err != nil {
			slog.Error("indieauth: validate token exchange", "err", err)
			http.Error(w, "invalid token exchange", http.StatusBadRequest)
			return
		}
		// The identity URL is the 'me' form value on the token exchange.
		me := r.FormValue("me")
		if me == "" {
			http.Error(w, "me is required", http.StatusBadRequest)
			return
		}
		tok, err := b.IssueToken(r.Context(), me, authReq.Scopes)
		if err != nil {
			internalError(w, "indieauth: issue token", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + tok + `","token_type":"Bearer"}`))
	}
}
