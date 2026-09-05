package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/selfagency/sovereign/internal/store"
)

// WebAuthnHandler exposes passkey registration and login over HTTP. It
// persists credentials in the store and carries begin/finish sessions in a
// short-lived in-memory TTL store.
type WebAuthnHandler struct {
	wa      *WebAuthn
	store   *store.Store
	session *SessionStore
}

// NewWebAuthnHandler builds a WebAuthn HTTP handler for the given origin.
func NewWebAuthnHandler(rpID, rpDisplayName, origin string, st *store.Store) (*WebAuthnHandler, error) {
	wa, err := NewWebAuthn(rpID, rpDisplayName, origin)
	if err != nil {
		return nil, err
	}
	return &WebAuthnHandler{
		wa:      wa,
		store:   st,
		session: NewSessionStore(5 * time.Minute),
	}, nil
}

// RegisterBegin starts passkey registration for a user.
func (h *WebAuthnHandler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	creation, session, err := h.wa.BeginRegistration(user)
	if err != nil {
		http.Error(w, "begin registration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Put(session.Challenge, session)
	writeJSON(w, http.StatusOK, creation)
}

// RegisterFinish validates the attestation and stores the credential.
func (h *WebAuthnHandler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, err := h.sessionFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cred, err := h.wa.FinishRegistration(user, session, r)
	if err != nil {
		http.Error(w, "finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Persist the credential (full JSON for round-trip).
	data, err := json.Marshal(cred)
	if err != nil {
		http.Error(w, "marshal credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.store.AddWebAuthnCredential(r.Context(), &store.WebAuthnCredential{
		ID:           string(cred.ID),
		UserID:       user.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Data:         data,
	}); err != nil {
		http.Error(w, "store credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Delete(session.Challenge)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// LoginBegin starts passkey login for a user.
func (h *WebAuthnHandler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	assertion, session, err := h.wa.BeginLogin(user)
	if err != nil {
		http.Error(w, "begin login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Put(session.Challenge, session)
	writeJSON(w, http.StatusOK, assertion)
}

// LoginFinish validates the assertion and returns the authenticated user.
func (h *WebAuthnHandler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, err := h.sessionFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cred, err := h.wa.FinishLogin(user, session, r)
	if err != nil {
		http.Error(w, "finish login: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Update the sign count.
	if err := h.store.UpdateWebAuthnSignCount(r.Context(), string(cred.ID), cred.Authenticator.SignCount); err != nil {
		http.Error(w, "update sign count: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.session.Delete(session.Challenge)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "user_id": user.ID})
}

// userFromRequest loads the user (by handle query param) and populates their
// WebAuthn credentials from the store.
func (h *WebAuthnHandler) userFromRequest(r *http.Request) (*User, error) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		return nil, errors.New("missing handle query param")
	}
	// The identity tenant owns all users.
	su, err := h.store.UserByHandle(r.Context(), "identity", handle)
	if err != nil {
		return nil, errors.New("unknown user")
	}
	return h.authUserFromStore(su)
}

// loadUserByID loads a user by ID and populates their WebAuthn credentials,
// mirroring userFromRequest but keyed on the authenticated user ID rather than
// a client-supplied handle. This is the B11 fix: registration derives the
// user from the authenticated session, never from a ?handle= query param.
func (h *WebAuthnHandler) loadUserByID(userID string) (*User, error) {
	su, err := h.store.UserByID(context.Background(), userID)
	if err != nil {
		return nil, errors.New("unknown user")
	}
	return h.authUserFromStore(su)
}

// authUserFromStore wraps a store user with its WebAuthn credentials.
func (h *WebAuthnHandler) authUserFromStore(su *store.User) (*User, error) {
	creds, err := h.store.ListWebAuthnCredentials(context.Background(), su.ID)
	if err != nil {
		return nil, err
	}
	user := &User{ID: su.ID, Handle: su.Handle, DisplayName: su.DisplayName}
	for i := range creds {
		var wc webauthn.Credential
		if err := json.Unmarshal(creds[i].Data, &wc); err != nil {
			continue
		}
		user.Credentials = append(user.Credentials, wc)
	}
	return user, nil
}

// BeginRegistrationUser starts passkey registration for an explicit user ID
// (derived from the authenticated session) and stores the begin session. It
// returns the creation options for the client.
func (h *WebAuthnHandler) BeginRegistrationUser(userID string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	user, err := h.loadUserByID(userID)
	if err != nil {
		return nil, nil, err
	}
	creation, session, err := h.wa.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	h.session.Put(session.Challenge, session)
	return creation, session, nil
}

// FinishRegistrationUser validates an attestation for an explicit user ID and
// persists the credential. It reads the begin session (challenge) and the
// credential response from the request. On success the caller is responsible
// for marking passkey setup complete.
func (h *WebAuthnHandler) FinishRegistrationUser(userID string, r *http.Request) error {
	user, err := h.loadUserByID(userID)
	if err != nil {
		return err
	}
	session, err := h.sessionFromRequest(r)
	if err != nil {
		return err
	}
	cred, err := h.wa.FinishRegistration(user, session, r)
	if err != nil {
		return err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	if err := h.store.AddWebAuthnCredential(r.Context(), &store.WebAuthnCredential{
		ID:           string(cred.ID),
		UserID:       user.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Data:         data,
	}); err != nil {
		return err
	}
	h.session.Delete(session.Challenge)
	return nil
}

// BeginLoginUniform starts a client-side discoverable (passkey) login that
// does not require a known user up front. The returned assertion options have
// an identical shape whether or not the caller names a real handle, so an
// unknown handle cannot be enumerated. It stores the begin session by
// challenge and returns the assertion options.
func (h *WebAuthnHandler) BeginLoginUniform() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	assertion, session, err := h.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, err
	}
	h.session.Put(session.Challenge, session)
	return assertion, session, nil
}

// FinishLoginUniform validates a discoverable assertion, resolves the user
// from the credential, and returns the authenticated user ID. It reads the
// begin session (challenge) and the assertion response from the request.
func (h *WebAuthnHandler) FinishLoginUniform(r *http.Request) (string, error) {
	session, err := h.sessionFromRequest(r)
	if err != nil {
		return "", err
	}
	resolver := func(rawID, userHandle []byte) (*User, error) {
		cred, err := h.store.GetWebAuthnCredential(r.Context(), rawID)
		if err != nil {
			return nil, err
		}
		return h.loadUserByID(cred.UserID)
	}
	user, cred, err := h.wa.FinishPasskeyLogin(resolver, session, r)
	if err != nil {
		return "", err
	}
	if err := h.store.UpdateWebAuthnSignCount(r.Context(), string(cred.ID), cred.Authenticator.SignCount); err != nil {
		return "", err
	}
	h.session.Delete(session.Challenge)
	return user.ID, nil
}

// sessionFromRequest loads the begin/finish session by challenge.
func (h *WebAuthnHandler) sessionFromRequest(r *http.Request) (*webauthn.SessionData, error) {
	challenge := r.URL.Query().Get("challenge")
	if challenge == "" {
		return nil, errors.New("missing challenge query param")
	}
	session, ok := h.session.Get(challenge)
	if !ok {
		return nil, errors.New("session not found or expired")
	}
	return session, nil
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SessionStore is a short-lived in-memory store for WebAuthn begin/finish
// sessions, keyed by challenge. Entries expire after a TTL.
type SessionStore struct {
	mu   sync.Mutex
	ttl  time.Duration
	data map[string]sessionEntry
}

type sessionEntry struct {
	session   *webauthn.SessionData
	expiresAt time.Time
}

// NewSessionStore builds a session store with the given TTL.
func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{ttl: ttl, data: map[string]sessionEntry{}}
}

// Put stores a session keyed by challenge.
func (s *SessionStore) Put(challenge string, session *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[challenge] = sessionEntry{session: session, expiresAt: time.Now().Add(s.ttl)}
}

// Get returns a non-expired session by challenge.
func (s *SessionStore) Get(challenge string) (*webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[challenge]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(s.data, challenge)
		return nil, false
	}
	return e.session, true
}

// Delete removes a session by challenge.
func (s *SessionStore) Delete(challenge string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, challenge)
}
