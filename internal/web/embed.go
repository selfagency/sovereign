// Package web embeds and serves the Sovereign web client: the shared browser
// module (api.js, simple.css) and the panel HTML shell. Assets are compiled
// into the binary with go:embed — there is no npm, no build step, and no
// runtime dependency on an external CDN. Every response carries a strict
// Content-Security-Policy so the client cannot load or execute anything the
// server did not ship.
package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed shared panel admin
var assets embed.FS

// ContentSecurityPolicy is the strict policy served with every asset: nothing
// is allowed by default; scripts, fetches, images, and styles must come from
// this origin; there is no base URI and no cross-origin form posts.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// contentTypes pins the Content-Type for the asset kinds the client ships.
// Pinning (rather than sniffing) keeps a mislabeled file from being treated as
// executable and pairs with X-Content-Type-Options: nosniff.
var contentTypes = map[string]string{
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".html":        "text/html; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".webmanifest": "application/manifest+json",
}

// Handler serves the embedded web tree. prefix is the URL path the handler is
// mounted under (e.g. "/web/") and is stripped before resolving the embedded
// file. A request that resolves to a directory serves that directory's
// index.html. Paths containing ".." are rejected outright, so traversal cannot
// escape the embedded tree before fs.FS's own checks apply.
func Handler(prefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, prefix)
		if strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}
		// An empty name is the mount root (e.g. /panel/ or /admin/): serve the
		// directory's index.html, same as any other directory request.
		if name == "" {
			name = "/"
		}
		name = path.Clean("/" + name)
		rel := strings.TrimPrefix(name, "/")

		// Resolve directories to their index.html before reading, so a
		// directory never produces a listing or a bogus content type.
		info, err := fs.Stat(assets, rel)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if info.IsDir() {
			rel = path.Join(rel, "index.html")
			name = path.Join(name, "index.html")
		}

		data, err := fs.ReadFile(assets, rel)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Type", contentType(name))
		h.Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}

// contentType returns the pinned Content-Type for name's extension, falling
// back to the platform table and finally to a non-executable default.
func contentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}
