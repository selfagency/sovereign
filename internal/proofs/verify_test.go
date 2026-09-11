package proofs

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// fakeResolver resolves hosts to fixed IPs.
type fakeResolver struct {
	ips map[string][]net.IPAddr
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, errors.New("no txt")
}

// TestVerifyDNS verifies DNS TXT token presence/absence.
func TestVerifyDNS(t *testing.T) {
	// Test the verifyDNS logic directly with a stub resolver.
	vr := &Verifier{Resolver: &stubTXTResolver{txts: map[string][]string{
		"_atproto.alice.example.com": {"did=did:plc:abc123"},
	}}}
	res, err := vr.Verify(context.Background(), &Claim{
		Service:       "dns",
		ClaimLocation: "_atproto.alice.example.com",
		ExpectedToken: "did:plc:abc123",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "verified" {
		t.Fatalf("status = %s, want verified", res.Status)
	}

	// Token absent.
	vr2 := &Verifier{Resolver: &stubTXTResolver{txts: map[string][]string{"x.example.com": {"v=spf1"}}}}
	res2, _ := vr2.Verify(context.Background(), &Claim{
		Service:       "dns",
		ClaimLocation: "x.example.com",
		ExpectedToken: "did:plc:abc123",
	})
	if res2.Status != "failed" {
		t.Fatalf("status = %s, want failed", res2.Status)
	}
}

// stubTXTResolver resolves TXT records.
type stubTXTResolver struct {
	txts map[string][]string
}

func (s *stubTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txts, ok := s.txts[name]; ok {
		return txts, nil
	}
	return nil, errors.New("no such host")
}

func (s *stubTXTResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return nil, errors.New("no ip")
}

// TestVerifyHTTPBody verifies HTTP body token presence.
func TestVerifyHTTPBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proof@ariadne.id=abc123"))
	}))
	defer srv.Close()

	// The SSRF check resolves the host; return a public IP so the check
	// passes (the actual request still goes to the loopback test server).
	host := hostFromURL(srv.URL)
	v := &Verifier{
		HTTPClient: srv.Client(),
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			host: {{IP: net.ParseIP("93.184.216.34")}},
		}},
	}
	res, err := v.Verify(context.Background(), &Claim{
		Service:       "custom_url",
		ClaimLocation: srv.URL,
		ExpectedToken: "abc123",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "verified" {
		t.Fatalf("status = %s, want verified", res.Status)
	}
}

// TestVerifyHTTPBodyTokenAcrossReads verifies a token that spans multiple
// Read calls is still found (audit D3): the body is scanned in full, not just
// the first chunk.
func TestVerifyHTTPBodyTokenAcrossReads(t *testing.T) {
	// A server that writes the token in tiny chunks so a single Read cannot
	// capture it whole.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, b := range []byte("proof@ariadne.id=abc123") {
			_, _ = w.Write([]byte{b})
		}
	}))
	defer srv.Close()

	host := hostFromURL(srv.URL)
	v := &Verifier{
		HTTPClient: srv.Client(),
		Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
			host: {{IP: net.ParseIP("93.184.216.34")}},
		}},
	}
	res, err := v.Verify(context.Background(), &Claim{
		Service:       "custom_url",
		ClaimLocation: srv.URL,
		ExpectedToken: "abc123",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != "verified" {
		t.Fatalf("status = %s, want verified (token spans reads)", res.Status)
	}
}

// TestVerifyUnsupportedService verifies an unsupported service errors.
func TestVerifyUnsupportedService(t *testing.T) {
	v := &Verifier{}
	if _, err := v.Verify(context.Background(), &Claim{Service: "xmpp"}); err == nil {
		t.Fatal("expected error for unsupported service")
	}
}

// TestRequireSafeURLPrivateIP verifies private IPs are blocked (release gate).
func TestRequireSafeURLPrivateIP(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"10.0.0.1": {{IP: net.ParseIP("10.0.0.1")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://10.0.0.1/", v.Resolver); err == nil {
		t.Fatal("expected error for private IP")
	}
}

// TestRequireSafeURLLoopback verifies loopback is rejected.
func TestRequireSafeURLLoopback(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"127.0.0.1": {{IP: net.ParseIP("127.0.0.1")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://127.0.0.1/", v.Resolver); err == nil {
		t.Fatal("expected error for loopback")
	}
}

// TestRequireSafeURLPublicIP verifies public IPs are allowed.
func TestRequireSafeURLPublicIP(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"example.com": {{IP: net.ParseIP("93.184.216.34")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://example.com/", v.Resolver); err != nil {
		t.Fatalf("public IP rejected: %v", err)
	}
}

// TestRequireSafeURLDNSRebind verifies a host resolving to a private IP is
// rejected even if the hostname looks public (DNS rebinding defense).
func TestRequireSafeURLDNSRebind(t *testing.T) {
	v := &Verifier{Resolver: &fakeResolver{ips: map[string][]net.IPAddr{
		"public.example.com": {{IP: net.ParseIP("169.254.169.254")}},
	}}}
	if err := requireSafeURL(context.Background(), "http://public.example.com/", v.Resolver); err == nil {
		t.Fatal("expected error for DNS-rebind to metadata IP")
	}
}

// TestHostFromURL verifies host extraction.
func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"http://example.com/path":  "example.com",
		"https://example.com:8443": "example.com",
		"http://10.0.0.1/":         "10.0.0.1",
		"example.com":              "example.com",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Fatalf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIsBlockedIP verifies IP classification.
func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "fe80::1"}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("isBlockedIP(%s) = false, want true", s)
		}
	}
	if isBlockedIP(net.ParseIP("93.184.216.34")) {
		t.Fatal("public IP should not be blocked")
	}
}

// TestSafeRedirectBlocksPrivateTarget verifies a redirect to a private/
// loopback address is rejected (audit D1): the initial URL is vetted, but a
// 302 can point at 169.254.169.254 or 127.0.0.1, so every redirect hop must
// be re-vetted for scheme + resolved IP.
func TestSafeRedirectBlocksPrivateTarget(t *testing.T) {
	resolver := &fakeResolver{ips: map[string][]net.IPAddr{
		"public.example.com": {{IP: net.ParseIP("93.184.216.34")}},
		"127.0.0.1":          {{IP: net.ParseIP("127.0.0.1")}},
		"169.254.169.254":    {{IP: net.ParseIP("169.254.169.254")}},
	}}

	// Redirect to loopback -> blocked.
	err := SafeRedirect(resolver)(&http.Request{URL: mustURL(t, "http://127.0.0.1/")}, nil)
	if err == nil {
		t.Fatal("redirect to loopback accepted, want error")
	}

	// Redirect to cloud metadata -> blocked.
	err = SafeRedirect(resolver)(&http.Request{URL: mustURL(t, "http://169.254.169.254/latest/meta-data/")}, nil)
	if err == nil {
		t.Fatal("redirect to metadata accepted, want error")
	}

	// Redirect to a public host -> allowed.
	err = SafeRedirect(resolver)(&http.Request{URL: mustURL(t, "http://public.example.com/next")}, nil)
	if err != nil {
		t.Fatalf("redirect to public host rejected: %v", err)
	}

	// Non-http scheme -> blocked.
	err = SafeRedirect(resolver)(&http.Request{URL: mustURL(t, "file:///etc/passwd")}, nil)
	if err == nil {
		t.Fatal("redirect to file scheme accepted, want error")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
