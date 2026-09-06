package server

import (
	"crypto/rsa"
	"html/template"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// panelHandler serves the user panel. It reads the session cookie, loads the
// user, and forces the first-login flow: accept ToS, then set up a passkey,
// then configure the profile. All pages are server-rendered stdlib templates
// styled with simple.css and restricted to the smolweb element subset.
func panelHandler(st *store.Store, key *rsa.PrivateKey, issuer, audience string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/panel", func(w http.ResponseWriter, r *http.Request) {
		u, ok := sessionUser(r, st, key, issuer, audience)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case !u.ToSAccepted:
			renderPanel(w, "tos", u, nil)
		case !u.PasskeySetup:
			renderPanel(w, "passkey", u, nil)
		default:
			page, _ := st.GetProfilePage(r.Context(), u.TenantID)
			renderPanel(w, "profile", u, page)
		}
	})
	mux.HandleFunc("/panel/tos", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		u, ok := sessionUser(r, st, key, issuer, audience)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := st.SetToSAccepted(r.Context(), u.ID, true); err != nil {
			http.Error(w, "tos error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/panel", http.StatusSeeOther)
	})
	// /panel/passkey marks passkey setup complete. The credential is
	// registered via the session-derived control-plane endpoints
	// (/api/v1/auth/webauthn/register/{begin,finish}); this endpoint flips the
	// onboarding flag once registration succeeds.
	mux.HandleFunc("/panel/passkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		u, ok := sessionUser(r, st, key, issuer, audience)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := st.SetPasskeySetup(r.Context(), u.ID, true); err != nil {
			http.Error(w, "passkey error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/panel", http.StatusSeeOther)
	})
	mux.HandleFunc("/panel/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		u, ok := sessionUser(r, st, key, issuer, audience)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		page := &store.ProfilePage{
			ID:          "profile-" + u.ID,
			TenantID:    u.TenantID,
			AccountID:   u.ID,
			DisplayName: strings.TrimSpace(r.FormValue("display_name")),
			Bio:         strings.TrimSpace(r.FormValue("bio")),
		}
		if err := st.UpsertProfilePage(r.Context(), page); err != nil {
			http.Error(w, "save profile: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/panel", http.StatusSeeOther)
	})
	return mux
}

// sessionUser loads the user from the session cookie, or returns ok=false.
func sessionUser(r *http.Request, st *store.Store, key *rsa.PrivateKey, issuer, audience string) (*store.User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	claims, err := auth.ValidateAccessToken(key, c.Value, issuer, audience)
	if err != nil {
		return nil, false
	}
	u, err := st.UserByID(r.Context(), claims.Subject)
	if err != nil {
		return nil, false
	}
	return u, true
}

// panelTemplates are the user-panel pages. They use only the smolweb element
// subset (form/fieldset/legend/label/input/button, semantic header/main/nav/
// section/footer) and are styled with simple.css.
var panelTemplates = template.Must(template.New("panel").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sovereign — {{.Title}}</title>
<link rel="stylesheet" href="https://cdn.simplecss.org/simple.min.css">
</head>
<body>
<header><h1>Sovereign</h1></header>
<main>
{{if eq .View "tos"}}
<section>
<h2>Terms of Service</h2>
<p>Welcome to Sovereign. Before you can use your account, please review and accept the Terms of Service.</p>
<form method="post" action="/panel/tos">
<fieldset>
<legend>Acceptance</legend>
<label><input type="checkbox" name="accept" value="1" required> I accept the Terms of Service</label>
</fieldset>
<button type="submit">Accept</button>
</form>
</section>
{{else if eq .View "passkey"}}
<section>
<h2>Set up your passkey</h2>
<p>Your account uses passkeys for authentication. Set one up now.</p>
<button id="register" type="button">Register passkey</button>
<p id="status"></p>
</section>
<script>
const status = document.getElementById("status");
const btn = document.getElementById("register");
btn.addEventListener("click", async () => {
  try {
    status.textContent = "Contacting server…";
    const begin = await fetch("/api/v1/auth/webauthn/register/begin", { method: "POST" });
    if (!begin.ok) throw new Error("begin failed: " + begin.status);
    const options = await begin.json();
    const cred = await navigator.credentials.create({ publicKey: options });
    const finish = await fetch("/api/v1/auth/webauthn/register/finish?challenge=" + encodeURIComponent(options.challenge), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cred)
    });
    if (!finish.ok) throw new Error("finish failed: " + finish.status);
    window.location.href = "/panel";
  } catch (e) {
    status.textContent = "Error: " + e.message;
  }
});
</script>
{{else}}
<section>
<h2>Your profile</h2>
<form method="post" action="/panel/profile">
<fieldset>
<legend>Profile</legend>
<label>Display name <input type="text" name="display_name" value="{{.DisplayName}}"></label>
<label>Bio <textarea name="bio" rows="4">{{.Bio}}</textarea></label>
</fieldset>
<button type="submit">Save</button>
</form>
</section>
{{end}}
</main>
<footer><p>Sovereign identity server</p></footer>
</body>
</html>`))

// panelData is the template data for a panel page.
type panelData struct {
	Title       string
	View        string
	Handle      string
	DisplayName string
	Bio         string
}

// renderPanel renders a panel page.
func renderPanel(w http.ResponseWriter, view string, u *store.User, page *store.ProfilePage) {
	data := panelData{View: view, Handle: u.Handle}
	switch view {
	case "tos":
		data.Title = "Terms of Service"
	case "passkey":
		data.Title = "Set up your passkey"
	default:
		data.Title = "Your profile"
		if page != nil {
			data.DisplayName = page.DisplayName
			data.Bio = page.Bio
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = panelTemplates.Execute(w, data)
}
