package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn wraps go-webauthn for passkey registration and login.
type WebAuthn struct {
	wa *webauthn.WebAuthn
}

// NewWebAuthn builds a WebAuthn relying party for the given origin.
func NewWebAuthn(rpID, rpDisplayName, origin string) (*WebAuthn, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     []string{origin},
	})
	if err != nil {
		return nil, err
	}
	return &WebAuthn{wa: wa}, nil
}

// BeginRegistration starts passkey registration for a user, returning the
// creation options for the client and a session to store.
func (w *WebAuthn) BeginRegistration(u *User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	user := &webauthnUser{u: u}
	creation, session, err := w.wa.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	return creation, session, nil
}

// FinishRegistration validates the client's attestation response and returns
// the stored credential.
func (w *WebAuthn) FinishRegistration(u *User, session *webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	user := &webauthnUser{u: u}
	return w.wa.FinishRegistration(user, *session, r)
}

// BeginDiscoverableLogin starts a client-side discoverable (passkey) login,
// which does not require a known user up front. It returns assertion options
// whose shape is identical for every caller, so an unknown handle cannot be
// distinguished from a known one (no user enumeration). This is the uniform
// login path used by the anonymous login/begin endpoint.
func (w *WebAuthn) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	assertion, session, err := w.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, err
	}
	return assertion, session, nil
}

// FinishPasskeyLogin validates a discoverable-login assertion against a
// handler that resolves the authenticated user from the credential, returning
// the user and the validated credential. The handler receives the credential's
// raw ID and the user handle from the authenticator response and must return
// an *auth.User (with Credentials populated) or an error; it is invoked when
// the client-side discoverable login does not identify the user up front.
func (w *WebAuthn) FinishPasskeyLogin(handler func(rawID, userHandle []byte) (*User, error), session *webauthn.SessionData, r *http.Request) (*User, *webauthn.Credential, error) {
	adapt := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := handler(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		return &webauthnUser{u: u}, nil
	}
	user, cred, err := w.wa.FinishPasskeyLogin(adapt, *session, r)
	if err != nil {
		return nil, nil, err
	}
	// The resolved user carries the ID/handle/display name from the store;
	// Credentials are populated by the caller's handler as needed.
	return &User{ID: string(user.WebAuthnID()), Handle: user.WebAuthnName(), DisplayName: user.WebAuthnDisplayName()}, cred, nil
}

// BeginLogin starts passkey login for a user, returning assertion options.
func (w *WebAuthn) BeginLogin(u *User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	user := &webauthnUser{u: u}
	assertion, session, err := w.wa.BeginLogin(user)
	if err != nil {
		return nil, nil, err
	}
	return assertion, session, nil
}

// FinishLogin validates the client's assertion and returns the credential.
func (w *WebAuthn) FinishLogin(u *User, session *webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	user := &webauthnUser{u: u}
	return w.wa.FinishLogin(user, *session, r)
}

// webauthnUser adapts *User to go-webauthn's User interface.
type webauthnUser struct {
	u *User
}

func (w *webauthnUser) WebAuthnID() []byte          { return []byte(w.u.ID) }
func (w *webauthnUser) WebAuthnName() string        { return w.u.Handle }
func (w *webauthnUser) WebAuthnDisplayName() string { return w.u.DisplayName }
func (w *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return w.u.Credentials
}

// SessionCodec serializes/deserializes WebAuthn sessions for cookie storage.
type SessionCodec struct{}

// Encode marshals a session to a JSON byte slice.
func (SessionCodec) Encode(s *webauthn.SessionData) ([]byte, error) {
	return json.Marshal(s)
}

// Decode unmarshals a session from a JSON byte slice.
func (SessionCodec) Decode(b []byte) (*webauthn.SessionData, error) {
	var s webauthn.SessionData
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ErrNoCredentials is returned when a user has no registered passkeys.
var ErrNoCredentials = errors.New("no credentials registered")
