// Package auth access-token support: short-lived signed JWTs used as bearer
// credentials at resource endpoints (remoteStorage, Solid). Refresh tokens are
// long-lived and are accepted ONLY at the OIDC token endpoint — never here.
package auth

import (
	"crypto/rsa"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// AccessTokenTTL is the default lifetime of a signed access token.
const AccessTokenTTL = 15 * time.Minute

// accessTokenType is the JWT typ header required on access tokens. It
// distinguishes access tokens from refresh tokens (token-type separation).
const accessTokenType = "JWT"

// AccessToken is the claim set carried by a signed resource-access token.
type AccessToken struct {
	Subject  string   `json:"sub"`
	WebID    string   `json:"webid,omitempty"`
	Scopes   []string `json:"scp"`
	Issuer   string   `json:"iss,omitempty"`
	Audience string   `json:"aud,omitempty"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	ID       string   `json:"jti"`
}

// MintAccessToken signs a short-lived access token for subject with the given
// scopes using the RSA signing key. webID, if non-empty, is carried as the
// Solid-OIDC webid claim (the agent's WebID at resource endpoints). issuer is
// the identity host (https://id.<domain>) and audience the configured audience;
// both are embedded in the token and enforced at validation.
func MintAccessToken(priv *rsa.PrivateKey, subject string, scopes []string, ttl time.Duration, issuer, audience string) (string, error) {
	return MintAccessTokenWebID(priv, subject, "", scopes, ttl, issuer, audience)
}

// MintAccessTokenWebID signs an access token with an explicit Solid-OIDC
// webid claim.
func MintAccessTokenWebID(priv *rsa.PrivateKey, subject, webID string, scopes []string, ttl time.Duration, issuer, audience string) (string, error) {
	if priv == nil {
		return "", errors.New("auth: nil signing key")
	}
	if ttl <= 0 {
		return "", errors.New("auth: ttl must be positive")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType(accessTokenType))
	if err != nil {
		return "", err
	}
	now := time.Now()
	id, err := newID()
	if err != nil {
		return "", err
	}
	claims := AccessToken{
		Subject:  subject,
		WebID:    webID,
		Scopes:   scopes,
		Issuer:   issuer,
		Audience: audience,
		Expiry:   now.Add(ttl).Unix(),
		IssuedAt: now.Unix(),
		ID:       id,
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// IssueForProfile mints an access token for an IndieAuth identity URL. The
// profile URL is the token's subject (the authenticated identity).
func IssueForProfile(priv *rsa.PrivateKey, profileURL string, scopes []string, issuer, audience string) (string, error) {
	if profileURL == "" {
		return "", errors.New("auth: profile URL is required")
	}
	return MintAccessToken(priv, profileURL, scopes, AccessTokenTTL, issuer, audience)
}

// ValidateAccessToken verifies the signature, token type, and claims of an
// access token and returns its claims. It rejects tokens that are expired,
// lack a non-zero future exp, have an empty sub, are signed by a different
// key, carry a non-JWT typ header, or whose iss/aud do not match the expected
// issuer (https://id.<domain>) and audience.
//
// Known limitations (accepted, fail-closed, revisit later):
//   - aud is compared as a single string; an array-form aud claim is rejected
//     (fail-closed, safe).
//   - nbf (not-before) is not checked; a token valid at iat is accepted.
func ValidateAccessToken(priv *rsa.PrivateKey, token, issuer, audience string) (*AccessToken, error) {
	if priv == nil {
		return nil, errors.New("auth: nil signing key")
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, errors.New("auth: invalid access token")
	}
	// Token-type separation: only JWT-typed tokens are accepted as access
	// tokens. Refresh tokens (and other types) are rejected here.
	if len(parsed.Headers) == 0 || parsed.Headers[0].ExtraHeaders[jose.HeaderType] != accessTokenType {
		return nil, errors.New("auth: invalid access token type")
	}
	var claims AccessToken
	if err := parsed.Claims(priv.Public(), &claims); err != nil {
		return nil, errors.New("auth: invalid access token signature")
	}
	if claims.Expiry == 0 {
		return nil, errors.New("auth: access token missing expiry")
	}
	if time.Now().After(time.Unix(claims.Expiry, 0)) {
		return nil, errors.New("auth: access token expired")
	}
	if claims.Subject == "" {
		return nil, errors.New("auth: access token missing subject")
	}
	if claims.Issuer != issuer {
		return nil, errors.New("auth: access token issuer mismatch")
	}
	if claims.Audience != audience {
		return nil, errors.New("auth: access token audience mismatch")
	}
	return &claims, nil
}
