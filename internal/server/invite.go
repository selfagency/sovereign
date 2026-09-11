package server

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// sessionCookie is the name of the HttpOnly session cookie set after a
// successful magic-link redemption.
const sessionCookie = "session"

// sessionTTL is the lifetime of a magic-link session access token.
const sessionTTL = 15 * time.Minute

// inviteHandler validates a one-time magic-link token, atomically marks it
// used, mints a short-lived session access token (subject = user ID), sets it
// as an HttpOnly cookie, and redirects to the user panel.
func inviteHandler(st *store.Store, key *rsa.PrivateKey, issuer, audience string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Path, "/invite/")
		if raw == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		// Atomic single-use gate: exactly one concurrent redemption succeeds.
		if err := st.RedeemInviteToken(r.Context(), hashToken(raw), time.Now()); err != nil {
			switch {
			case errors.Is(err, store.ErrInviteUsed), errors.Is(err, store.ErrInviteExpired):
				http.Error(w, "invite unavailable", http.StatusGone)
			default:
				http.NotFound(w, r)
			}
			return
		}
		// Fetch the invited user ID for session minting.
		it, err := st.InviteTokenByHash(r.Context(), hashToken(raw))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// Reject tokens whose user was deleted: never mint a session for a
		// non-existent subject.
		if _, err := st.UserByID(r.Context(), it.UserID); err != nil {
			http.Error(w, "invite unavailable", http.StatusGone)
			return
		}
		// Mint a short-lived session access token for the invited user.
		tok, err := auth.MintAccessToken(key, it.UserID, []string{"self"}, sessionTTL, issuer, audience)
		if err != nil {
			internalError(w, "invite: mint session", err)
			return
		}
		// The identity host is always served over HTTPS, so the session cookie
		// is always Secure. HttpOnly and SameSite are always on. The cookie
		// carries a short-lived signed session token, not a long-lived
		// credential.
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    tok,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionTTL.Seconds()),
		})
		http.Redirect(w, r, "/panel", http.StatusFound)
	})
}

// hashToken returns the hex SHA-256 hash of a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
