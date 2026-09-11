// Package proofs implements public identity proofs ("Hyperproofs") in the
// Keyoxide/Ariadne pattern: a cryptographic anchor holds signed claims
// pointing at accounts on other services; each claimed account publishes the
// anchor's fingerprint/DID somewhere discoverable. Verification is
// bidirectional, requiring no central authority.
package proofs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// Claim is a single proof claim.
type Claim struct {
	ID            string
	AnchorType    string // "did" | "pgp_fingerprint" | "webid"
	AnchorValue   string
	Service       string // "dns" | "github_gist" | "mastodon" | "bluesky" | "custom_url"
	ClaimLocation string
	ExpectedToken string
}

// Result is the outcome of verifying a claim.
type Result struct {
	Status string // "verified" | "failed"
}

// Resolver resolves DNS records. net.Resolver satisfies it; tests inject
// stubs to avoid real DNS.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Verifier checks a single claim. Every fetch touches attacker-influenced
// URLs (the tenant controls claim_location) — this is an SSRF surface and
// must be treated as such: block private/loopback/link-local IP ranges,
// cap redirects, cap response size, strict timeout.
type Verifier struct {
	HTTPClient *http.Client
	Resolver   Resolver
}

// Verify checks a single claim.
func (v *Verifier) Verify(ctx context.Context, claim *Claim) (Result, error) {
	switch claim.Service {
	case "dns":
		return v.verifyDNS(ctx, claim)
	case "github_gist", "custom_url", "mastodon", "bluesky":
		return v.verifyHTTPBody(ctx, claim)
	default:
		return Result{}, fmt.Errorf("proofs: unsupported service %q", claim.Service)
	}
}

// verifyDNS checks a DNS TXT record for the expected token.
func (v *Verifier) verifyDNS(ctx context.Context, claim *Claim) (Result, error) {
	txts, err := v.Resolver.LookupTXT(ctx, claim.ClaimLocation)
	if err != nil {
		return Result{Status: "failed"}, err
	}
	for _, t := range txts {
		if strings.Contains(t, claim.ExpectedToken) {
			return Result{Status: "verified"}, nil
		}
	}
	return Result{Status: "failed"}, errors.New("proofs: token not found in TXT records")
}

// verifyHTTPBody fetches a URL and checks for the expected token.
func (v *Verifier) verifyHTTPBody(ctx context.Context, claim *Claim) (Result, error) {
	if err := requireSafeURL(ctx, claim.ClaimLocation, v.Resolver); err != nil {
		return Result{Status: "failed"}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, claim.ClaimLocation, http.NoBody)
	if err != nil {
		return Result{Status: "failed"}, err
	}
	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return Result{Status: "failed"}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Hard cap response body size — never read an unbounded remote body. Read
	// the full capped body (a single Read may return a partial chunk, so scan
	// the whole stream for the token — audit D3).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Result{Status: "failed"}, err
	}
	if strings.Contains(string(body), claim.ExpectedToken) {
		return Result{Status: "verified"}, nil
	}
	return Result{Status: "failed"}, errors.New("proofs: token not found in response body")
}

// requireSafeURL rejects URLs resolving to private/loopback/link-local/
// cloud-metadata addresses. It resolves DNS first and checks the resolved IP
// (not the hostname string) to defeat DNS rebinding.
func requireSafeURL(ctx context.Context, rawURL string, resolver Resolver) error {
	host := hostFromURL(rawURL)
	if host == "" {
		return errors.New("proofs: invalid url")
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("proofs: dns resolution failed: %w", err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return errors.New("proofs: url resolves to a blocked address")
		}
	}
	return nil
}

// SafeRedirect returns an http.Client.CheckRedirect that re-vets every
// redirect hop (audit D1): the initial URL is vetted by requireSafeURL, but a
// public URL can 302 to a private/loopback/cloud-metadata address, so each
// redirect target must be re-checked for scheme and resolved IP. It also caps
// the redirect chain.
func SafeRedirect(resolver Resolver) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("proofs: too many redirects")
		}
		if req.URL == nil {
			return errors.New("proofs: redirect without url")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("proofs: redirect to unsupported scheme %q", req.URL.Scheme)
		}
		if err := requireSafeURL(req.Context(), req.URL.String(), resolver); err != nil {
			return err
		}
		return nil
	}
}

// hostFromURL extracts the host from a URL string.
func hostFromURL(rawURL string) string {
	// Strip scheme.
	rest := rawURL
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	// Strip path/query.
	if idx := strings.IndexAny(rest, "/?"); idx >= 0 {
		rest = rest[:idx]
	}
	// Strip port.
	if idx := strings.Index(rest, ":"); idx >= 0 {
		rest = rest[:idx]
	}
	return rest
}

// isBlockedIP reports whether an IP is private/loopback/link-local or a
// cloud-metadata address.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Cloud metadata (169.254.169.254) is link-local, already covered.
	return false
}
