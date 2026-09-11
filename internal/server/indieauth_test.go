package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.hacdias.com/indielib/indieauth"

	ia "github.com/selfagency/sovereign/internal/protocols/indieauth"
)

// fakeIssuer is a controllable indieauth.TokenIssuer.
type fakeIssuer struct {
	token string
	err   error
}

func (f *fakeIssuer) IssueForProfile(_ context.Context, _ string, _ []string) (string, error) {
	return f.token, f.err
}

// TestIndieAuthSessionExpiry proves an expired session entry is evicted and
// get returns false.
func TestIndieAuthSessionExpiry(t *testing.T) {
	s := newIndieAuthSessionStore()
	req := &indieauth.AuthenticationRequest{State: "stale"}
	s.data["stale"] = indieAuthSessionEntry{req: req, expiresAt: time.Now().Add(-time.Minute)}
	if _, ok := s.get("stale"); ok {
		t.Fatal("expired session should not be returned")
	}
	if _, ok := s.data["stale"]; ok {
		t.Fatal("expired session should be evicted")
	}
}

// TestIndieAuthSessionPutGet proves a fresh entry round-trips.
func TestIndieAuthSessionPutGet(t *testing.T) {
	s := newIndieAuthSessionStore()
	req := &indieauth.AuthenticationRequest{State: "fresh"}
	s.put("fresh", req)
	got, ok := s.get("fresh")
	if !ok || got != req {
		t.Fatalf("get = %v, %v; want req, true", got, ok)
	}
}

// TestIndieAuthAuthorizeParseError proves a malformed authorization request
// returns 400.
func TestIndieAuthAuthorizeParseError(t *testing.T) {
	b := ia.NewBridge(true, &fakeIssuer{})
	h := indieAuthAuthorize(b, newIndieAuthSessionStore())
	rec := httptest.NewRecorder()
	// Missing required params -> parse error.
	req := httptest.NewRequest(http.MethodGet, "/indieauth/auth", http.NoBody)
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestIndieAuthTokenUnknownCode proves an unknown/expired code returns 400.
func TestIndieAuthTokenUnknownCode(t *testing.T) {
	b := ia.NewBridge(true, &fakeIssuer{})
	h := indieAuthToken(b, newIndieAuthSessionStore())
	rec := httptest.NewRecorder()
	form := url.Values{}
	form.Set("code", "nope")
	req := httptest.NewRequest(http.MethodPost, "/indieauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestIndieAuthTokenMissingMe proves a valid code but missing 'me' returns
// 400.
func TestIndieAuthTokenMissingMe(t *testing.T) {
	b := ia.NewBridge(true, &fakeIssuer{})
	sessions := newIndieAuthSessionStore()

	// Authorize first to seed a valid session (PKCE + redirect must match the
	// later token exchange).
	verifier, challenge := pkcePair()
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", "https://app.example.com/app")
	authParams.Set("redirect_uri", "https://app.example.com/cb")
	authParams.Set("state", "code1")
	authParams.Set("me", "https://alice.example.com/profile")
	authParams.Set("code_challenge", challenge)
	authParams.Set("code_challenge_method", "S256")
	authReq, err := b.ParseAuthorization(httptest.NewRequest(http.MethodGet, "/indieauth/auth?"+authParams.Encode(), http.NoBody))
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	sessions.put("code1", authReq)

	h := indieAuthToken(b, sessions)
	rec := httptest.NewRecorder()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "code1")
	form.Set("client_id", "https://app.example.com/app")
	form.Set("redirect_uri", "https://app.example.com/cb")
	form.Set("code_verifier", verifier)
	// No 'me' field.
	req := httptest.NewRequest(http.MethodPost, "/indieauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing me)", rec.Code)
	}
}

// TestIndieAuthTokenParseFormError proves a malformed form body returns 400.
func TestIndieAuthTokenParseFormError(t *testing.T) {
	b := ia.NewBridge(true, &fakeIssuer{})
	h := indieAuthToken(b, newIndieAuthSessionStore())
	rec := httptest.NewRecorder()
	// Invalid form encoding (bad percent-escape) -> ParseForm error.
	req := httptest.NewRequest(http.MethodPost, "/indieauth/token", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestIndieAuthTokenValidateExchangeError proves a failed token-exchange
// validation returns 400.
func TestIndieAuthTokenValidateExchangeError(t *testing.T) {
	b := ia.NewBridge(true, &fakeIssuer{})
	sessions := newIndieAuthSessionStore()

	// Seed a session with a state that will fail ValidateTokenExchange: the
	// bridge requires the client_id/redirect_uri to match the authorization
	// request, so send a mismatched client_id.
	verifier, challenge := pkcePair()
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", "https://app.example.com/app")
	authParams.Set("redirect_uri", "https://app.example.com/cb")
	authParams.Set("state", "code1")
	authParams.Set("me", "https://alice.example.com/profile")
	authParams.Set("code_challenge", challenge)
	authParams.Set("code_challenge_method", "S256")
	authReq, err := b.ParseAuthorization(httptest.NewRequest(http.MethodGet, "/indieauth/auth?"+authParams.Encode(), http.NoBody))
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	sessions.put("code1", authReq)

	h := indieAuthToken(b, sessions)
	rec := httptest.NewRecorder()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "code1")
	form.Set("client_id", "https://evil.example.com/app") // mismatch
	form.Set("redirect_uri", "https://app.example.com/cb")
	form.Set("me", "https://alice.example.com/profile")
	form.Set("code_verifier", verifier)
	req := httptest.NewRequest(http.MethodPost, "/indieauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestIndieAuthTokenIssuanceError proves a token-issuance failure returns 500.
func TestIndieAuthTokenIssuanceError(t *testing.T) {
	b := ia.NewBridge(true, &fakeIssuer{err: errors.New("mint failed")})
	sessions := newIndieAuthSessionStore()

	// Authorize first to seed a valid session (PKCE + redirect must match the
	// later token exchange).
	verifier, challenge := pkcePair()
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", "https://app.example.com/app")
	authParams.Set("redirect_uri", "https://app.example.com/cb")
	authParams.Set("state", "code1")
	authParams.Set("me", "https://alice.example.com/profile")
	authParams.Set("code_challenge", challenge)
	authParams.Set("code_challenge_method", "S256")
	authReq, err := b.ParseAuthorization(httptest.NewRequest(http.MethodGet, "/indieauth/auth?"+authParams.Encode(), http.NoBody))
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	sessions.put("code1", authReq)

	h := indieAuthToken(b, sessions)
	rec := httptest.NewRecorder()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "code1")
	form.Set("client_id", "https://app.example.com/app")
	form.Set("redirect_uri", "https://app.example.com/cb")
	form.Set("me", "https://alice.example.com/profile")
	form.Set("code_verifier", verifier)
	req := httptest.NewRequest(http.MethodPost, "/indieauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
