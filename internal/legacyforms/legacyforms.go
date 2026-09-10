// Package legacyforms serves the no-JS form fallback for the user panel:
// Terms-of-Service acceptance and profile editing post directly to the store,
// so onboarding keeps working without JavaScript. WebAuthn is deliberately
// absent here — passkey registration is JS-only (see the thin client).
//
// Every rendered form carries a hidden csrf_token field whose value matches
// the __Host-csrf cookie. The CSRF middleware (internal/api/middleware)
// enforces the synchronizer-token check on form-encoded POSTs by reading that
// field, so the adapter must be mounted behind that middleware and must set
// the cookie on GET when it is absent.
package legacyforms

import (
	"crypto/rsa"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

const (
	// sessionCookie is the session cookie name set by the auth handler.
	sessionCookie = "session"
	// csrfCookieName mirrors middleware's unexported __Host-csrf cookie name.
	// SetToken (exported) writes the cookie; the adapter reads it back by name
	// so the hidden field echoes the exact value the middleware will compare.
	csrfCookieName = "__Host-csrf"
	// panelPath is where a successful form POST redirects (303).
	panelPath = "/panel"
)

// Adapter serves the no-JS panel forms over the store.
type Adapter struct {
	store    *store.Store
	key      *rsa.PrivateKey
	issuer   string
	audience string
}

// NewHandler returns the no-JS ToS and profile form handler. Mount it behind
// the CSRF middleware; the middleware performs the form-encoded token check,
// the adapter only renders the matching hidden field and the cookie.
func NewHandler(st *store.Store, key *rsa.PrivateKey, issuer, audience string) http.Handler {
	a := &Adapter{store: st, key: key, issuer: issuer, audience: audience}
	mux := http.NewServeMux()
	mux.HandleFunc("/panel/tos", a.tos)
	mux.HandleFunc("/panel/profile", a.profile)
	return mux
}

// tos serves the ToS form and accepts it on POST.
func (a *Adapter) tos(w http.ResponseWriter, r *http.Request) {
	u, ok := a.sessionUser(r)
	if !ok {
		http.Error(w, "legacyforms: unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		if err := a.store.SetToSAccepted(r.Context(), u.ID, true); err != nil {
			http.Error(w, "legacyforms: could not accept terms", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, panelPath, http.StatusSeeOther)
	case http.MethodGet, http.MethodHead:
		tok, err := a.csrfToken(w, r)
		if err != nil {
			http.Error(w, "legacyforms: could not render form", http.StatusInternalServerError)
			return
		}
		renderForm(w, tosTemplate, formData{Token: tok})
	default:
		http.Error(w, "legacyforms: method not allowed", http.StatusMethodNotAllowed)
	}
}

// profile serves the profile edit form and saves it on POST.
func (a *Adapter) profile(w http.ResponseWriter, r *http.Request) {
	u, ok := a.sessionUser(r)
	if !ok {
		http.Error(w, "legacyforms: unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		page := &store.ProfilePage{
			ID:          "profile-" + u.ID,
			TenantID:    u.TenantID,
			AccountID:   u.ID,
			DisplayName: strings.TrimSpace(r.FormValue("display_name")),
			Bio:         strings.TrimSpace(r.FormValue("bio")),
			UpdatedAt:   time.Now().UTC(),
		}
		if err := a.store.UpsertProfilePage(r.Context(), page); err != nil {
			http.Error(w, "legacyforms: could not save profile", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, panelPath, http.StatusSeeOther)
	case http.MethodGet, http.MethodHead:
		tok, err := a.csrfToken(w, r)
		if err != nil {
			http.Error(w, "legacyforms: could not render form", http.StatusInternalServerError)
			return
		}
		data := formData{Token: tok}
		if page, err := a.store.GetProfilePage(r.Context(), u.TenantID); err == nil {
			data.DisplayName = page.DisplayName
			data.Bio = page.Bio
		}
		renderForm(w, profileTemplate, data)
	default:
		http.Error(w, "legacyforms: method not allowed", http.StatusMethodNotAllowed)
	}
}

// sessionUser loads the user from the session cookie JWT, or reports ok=false.
func (a *Adapter) sessionUser(r *http.Request) (*store.User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	claims, err := auth.ValidateAccessToken(a.key, c.Value, a.issuer, a.audience)
	if err != nil {
		return nil, false
	}
	u, err := a.store.UserByID(r.Context(), claims.Subject)
	if err != nil {
		return nil, false
	}
	return u, true
}

// csrfToken returns the current __Host-csrf token, minting and setting a fresh
// one when the request carries no cookie. The returned value is rendered into
// the form's hidden field so it matches the cookie the middleware compares.
func (a *Adapter) csrfToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value, nil
	}
	tok, err := middleware.NewToken()
	if err != nil {
		return "", fmt.Errorf("legacyforms: generate csrf token: %w", err)
	}
	middleware.SetToken(w, tok)
	return tok, nil
}

// formData is the shared template data for both no-JS forms.
type formData struct {
	Token       string
	DisplayName string
	Bio         string
}

// renderForm writes a form page as HTML.
func renderForm(w http.ResponseWriter, tmpl *template.Template, data formData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

// tosTemplate is the no-JS ToS acceptance page. It uses only the smolweb
// element subset (form/fieldset/legend/label/input/button).
var tosTemplate = template.Must(template.New("tos").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sovereign — Terms of Service</title>
</head>
<body>
<main>
<section>
<h2>Terms of Service</h2>
<p>Review and accept the Terms of Service to continue.</p>
<form method="post" action="/panel/tos">
<fieldset>
<legend>Acceptance</legend>
<input type="hidden" name="csrf_token" value="{{.Token}}">
<label><input type="checkbox" name="accept" value="1" required> I accept the Terms of Service</label>
</fieldset>
<button type="submit">Accept</button>
</form>
</section>
</main>
</body>
</html>`))

// profileTemplate is the no-JS profile edit page.
var profileTemplate = template.Must(template.New("profile").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sovereign — Your profile</title>
</head>
<body>
<main>
<section>
<h2>Your profile</h2>
<form method="post" action="/panel/profile">
<fieldset>
<legend>Profile</legend>
<input type="hidden" name="csrf_token" value="{{.Token}}">
<label>Display name <input type="text" name="display_name" value="{{.DisplayName}}"></label>
<label>Bio <textarea name="bio" rows="4">{{.Bio}}</textarea></label>
</fieldset>
<button type="submit">Save</button>
</form>
</section>
</main>
</body>
</html>`))
