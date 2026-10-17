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

func TestCallbackURL(t *testing.T) {
	cases := []struct {
		name        string
		appURL      string
		target      string
		forwardedTo string
		want        string
	}{
		{
			name:   "prefers AppURL",
			appURL: "https://app.example.com/",
			target: "http://internal:8156/auth/login",
			want:   "https://app.example.com/auth/callback",
		},
		{
			name:   "derives from the request without AppURL",
			appURL: "",
			target: "https://app.example.com:8156/auth/login",
			want:   "https://app.example.com:8156/auth/callback",
		},
		{
			name:        "honours X-Forwarded-Proto",
			appURL:      "",
			target:      "http://app:8156/auth/login",
			forwardedTo: "https",
			want:        "https://app:8156/auth/callback",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfig()
			config.AppURL = tc.appURL
			auth := &Auth{Settings: func() Config { return config }, CallbackPath: "/auth/callback"}

			_, req := newTestContext(http.MethodGet, tc.target)
			if tc.forwardedTo != "" {
				req.Header.Set("X-Forwarded-Proto", tc.forwardedTo)
			}

			if got := auth.callbackURL(req); got != tc.want {
				t.Errorf("callbackURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
