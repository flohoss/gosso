package gosso

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func httptestRequest(t *testing.T, target string) *http.Request {
	t.Helper()

	return httptest.NewRequest(http.MethodGet, target, nil)
}

func TestScheme_PrefersForwardedProto(t *testing.T) {
	req := httptestRequest(t, "http://app.test/")
	req.Header.Set("X-Forwarded-Proto", "https")

	if got := Scheme(req); got != "https" {
		t.Fatalf("Scheme() = %q, want %q", got, "https")
	}
}

func TestScheme_UsesTLSState(t *testing.T) {
	req := httptestRequest(t, "https://app.test/")

	if got := Scheme(req); got != "https" {
		t.Fatalf("Scheme() = %q, want %q", got, "https")
	}
}

func TestScheme_FallsBackToHTTP(t *testing.T) {
	req := httptestRequest(t, "http://app.test/")

	if got := Scheme(req); got != "http" {
		t.Fatalf("Scheme() = %q, want %q", got, "http")
	}
}
