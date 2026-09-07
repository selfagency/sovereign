package proofs

import "testing"

// TestFieldErrorError verifies the fieldError Error() method renders the
// field: detail string. This method is not called by the handler (which reads
// .field/.detail directly), so it is covered here directly.
func TestFieldErrorError(t *testing.T) {
	e := &fieldError{field: "service", detail: "bad"}
	if got := e.Error(); got != "service: bad" {
		t.Fatalf("Error() = %q, want %q", got, "service: bad")
	}
}

// TestIsHTTPURLBranches verifies the empty-string and parse-error branches of
// isHTTPURL, which are not reachable through the handler's validateCreate
// (empty claim_location is rejected earlier).
func TestIsHTTPURLBranches(t *testing.T) {
	if isHTTPURL("") {
		t.Fatal("empty URL should be invalid")
	}
	if isHTTPURL("://bad") {
		t.Fatal("unparseable URL should be invalid")
	}
	if !isHTTPURL("https://example.com") {
		t.Fatal("https URL should be valid")
	}
}
