package gosso

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/labstack/echo/v5"
)

func newOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()

	oidcServer := &oidctest.Server{}
	server := httptest.NewServer(oidcServer)
	t.Cleanup(server.Close)
	oidcServer.SetIssuer(server.URL)

	return server
}

func newTestAuth(t *testing.T) *Auth {
	t.Helper()

	sessions := newHMACSessions()

	return New(testSettingsFn(), sessions, "/auth/callback", "/login")
}

func testSettingsFn() func() Config {
	return func() Config { return testConfig() }
}

func TestNew_DisabledDoesNotWarmProvider(t *testing.T) {
	config := testConfig()
	config.Enabled = false
	auth := New(func() Config { return config }, newHMACSessions(), "/auth/callback", "/login")

	rec := serveWithAuth(auth, "/anything", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected open access while disabled, got %d", rec.Code)
	}
}

func TestAuth_EnabledFollowsConfig(t *testing.T) {
	config := testConfig()
	config.Enabled = true
	auth := &Auth{Settings: func() Config { return config }}

	if !auth.Enabled() {
		t.Fatal("expected auth to be enabled")
	}

	config.Enabled = false
	if auth.Enabled() {
		t.Fatal("expected auth to be disabled after the reload")
	}
}

func TestStartLogin_RedirectsToProviderWithStateCookie(t *testing.T) {
	server := newOIDCServer(t)
	config := testConfig()
	config.IssuerURL = server.URL
	auth := New(func() Config { return config }, newHMACSessions(), "/auth/callback", "/login")

	e := echo.New()
	authHandler := func(c *echo.Context) error {
		return auth.StartLogin(c, "/after/login")
	}
	e.GET("/auth/oidc", authHandler)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected a redirect, got %d", rec.Code)
	}

	location := rec.Header().Get(echo.HeaderLocation)
	if !strings.HasPrefix(location, server.URL+"/auth?") {
		t.Fatalf("expected a redirect to the provider, got %q", location)
	}
	if !strings.Contains(location, "code_challenge_method=S256") {
		t.Fatal("expected a S256 code challenge")
	}

	var stateCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if strings.HasSuffix(cookie.Name, "_oidc_state") {
			stateCookie = cookie
		}
	}
	if stateCookie == nil {
		t.Fatal("expected a state cookie")
	}
	if stateCookie.MaxAge != int(stateCookieTTL.Seconds()) {
		t.Fatalf("expected the state cookie to be short-lived, got %d", stateCookie.MaxAge)
	}
	if !stateCookie.HttpOnly {
		t.Fatal("expected the state cookie to be HttpOnly")
	}
	if !strings.Contains(stateCookie.Value, "|") || !strings.Contains(stateCookie.Value, "/after/login") {
		t.Fatalf("expected state|verifier|redirect, got %q", stateCookie.Value)
	}
}

func TestStartLogin_FailsWhenProviderUnavailable(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }, provider: NewProvider(func() Config { return config })}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := auth.StartLogin(c, "/")

	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
}

func TestConsumeLoginState_ParsesAllParts(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }}

	echoContext, _ := newTestContext(http.MethodGet, "/")
	value := "state-token|verifier-token|/jobs/1"
	echoContext.Request().AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: value})

	state, verifier, redirect, err := auth.ConsumeLoginState(echoContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if state != "state-token" || verifier != "verifier-token" || redirect != "/jobs/1" {
		t.Fatalf("unexpected parse result: %q %q %q", state, verifier, redirect)
	}
}

func TestConsumeLoginState_RejectsMissingCookie(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }}

	echoContext, _ := newTestContext(http.MethodGet, "/")

	if _, _, _, err := auth.ConsumeLoginState(echoContext); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestConsumeLoginState_RejectsIncompleteValue(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }}

	echoContext, _ := newTestContext(http.MethodGet, "/")
	echoContext.Request().AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: "only-state"})

	if _, _, _, err := auth.ConsumeLoginState(echoContext); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestSanitizeRedirect(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		valid string
	}{
		{name: "empty", raw: "", valid: "/"},
		{name: "root", raw: "/", valid: "/"},
		{name: "path", raw: "/jobs/1", valid: "/jobs/1"},
		{name: "absolute", raw: "https://evil.example.com", valid: "/"},
		{name: "protocol relative", raw: "//evil.example.com", valid: "/"},
		{name: "backslash", raw: "/\\evil", valid: "/\\evil"},
	}

	for _, tc := range cases {
		if got := SanitizeRedirect(tc.raw); got != tc.valid {
			t.Errorf("%s: SanitizeRedirect(%q) = %q, want %q", tc.name, tc.raw, got, tc.valid)
		}
	}
}

func TestCallbackURL_PrefersAppUrl(t *testing.T) {
	config := testConfig()
	config.AppURL = "https://app.example.com/"
	auth := &Auth{Settings: func() Config { return config }, CallbackPath: "/auth/callback"}

	echoContext, _ := newTestContext(http.MethodGet, "http://internal:8156/auth/login")

	if got := auth.callbackURL(echoContext); got != "https://app.example.com/auth/callback" {
		t.Fatalf("callbackURL() = %q, want %q", got, "https://app.example.com/auth/callback")
	}
}

func TestCallbackURL_DerivesFromRequestWithoutAppUrl(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }, CallbackPath: "/auth/callback"}

	echoContext, _ := newTestContext(http.MethodGet, "http://app.example.com:8156/auth/login")

	if got := auth.callbackURL(echoContext); got != "http://app.example.com:8156/auth/callback" {
		t.Fatalf("callbackURL() = %q, want %q", got, "http://app.example.com:8156/auth/callback")
	}
}

func TestMiddleware_LoginPathRedirectsUnauthenticated(t *testing.T) {
	auth := newTestAuth(t)

	rec := serveWithAuth(auth, "/", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected a redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/login" {
		t.Fatalf("expected a redirect to /login, got %q", location)
	}
}

func TestMiddleware_WithoutLoginPathReturnsUnauthorized(t *testing.T) {
	auth := newTestAuth(t)
	auth.LoginPath = ""

	rec := serveWithAuth(auth, "/", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestSessionTTL_FollowsConfig(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }}

	if auth.SessionTTL() != time.Hour {
		t.Fatalf("expected the configured TTL, got %v", auth.SessionTTL())
	}

	config.SessionTTL = 0
	if auth.SessionTTL() != DefaultSessionTTL {
		t.Fatalf("expected the default TTL, got %v", auth.SessionTTL())
	}
}
