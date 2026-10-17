package gosso

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
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

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc", nil)

	if err := auth.StartLogin(rec, req, "/after/login"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusFound {
		t.Fatalf("expected a redirect, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
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

func TestStartLogin_RejectsInvalidConfig(t *testing.T) {
	config := testConfig()
	config.ClientSecret = ""
	auth := &Auth{Settings: func() Config { return config }, provider: NewProvider(func() Config { return config })}

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc", nil)
	rec := httptest.NewRecorder()

	if err := auth.StartLogin(rec, req, "/"); !errors.Is(err, ErrMissingOIDCFields) {
		t.Fatalf("expected ErrMissingOIDCFields, got %v", err)
	}
}

func TestStartLogin_FailsWhenProviderUnavailable(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }, provider: NewProvider(func() Config { return config })}

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc", nil)
	rec := httptest.NewRecorder()

	err := auth.StartLogin(rec, req, "/")

	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
}

func TestConsumeLoginState_ParsesAllParts(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }}

	rec, req := newTestContext(http.MethodGet, "/")
	value := "state-token|verifier-token|/jobs/1"
	req.AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: value})

	state, verifier, redirect, err := auth.ConsumeLoginState(rec, req)
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

	rec, req := newTestContext(http.MethodGet, "/")

	if _, _, _, err := auth.ConsumeLoginState(rec, req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestConsumeLoginState_RejectsIncompleteValue(t *testing.T) {
	config := testConfig()
	auth := &Auth{Settings: func() Config { return config }}

	rec, req := newTestContext(http.MethodGet, "/")
	req.AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: "only-state"})

	if _, _, _, err := auth.ConsumeLoginState(rec, req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestMiddleware_LoginPathRedirectsUnauthenticated(t *testing.T) {
	auth := newTestAuth(t)

	rec := serveWithAuth(auth, "/", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected a redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/login" {
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

func TestAuth_EnabledToleratesNilReceiver(t *testing.T) {
	var auth *Auth

	if auth.Enabled() {
		t.Fatal("expected a nil Auth to be disabled")
	}
}

func TestPrefix_FallsBackToSanitizedClientID(t *testing.T) {
	config := testConfig()
	config.ClientID = "My-App-Client"
	auth := &Auth{Settings: func() Config { return config }}

	if got := auth.prefix(); got != "myappclient" {
		t.Fatalf("prefix() = %q, want %q", got, "myappclient")
	}

	config.CookiePrefix = "custom"
	if got := auth.prefix(); got != "custom" {
		t.Fatalf("prefix() = %q, want %q", got, "custom")
	}
}

func TestCallbackURL_MatchesInternal(t *testing.T) {
	config := testConfig()
	config.AppURL = "https://app.example.com"
	auth := &Auth{Settings: func() Config { return config }, CallbackPath: "/auth/callback"}

	_, req := newTestContext(http.MethodGet, "http://internal:8156/auth/login")

	if got, want := auth.callbackURL(req), "https://app.example.com/auth/callback"; got != want {
		t.Fatalf("callbackURL() = %q, want %q", got, want)
	}
}

func TestStartSessionAndClearSessionRoundTrip(t *testing.T) {
	auth := newTestAuth(t)
	rec, req := newTestContext(http.MethodGet, "/")

	if err := auth.StartSession(rec, req, "user-subject"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var session *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.Sessions.CookieName() {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("expected a session cookie after StartSession")
	}

	subject, _, err := VerifyHMAC(testSessionKey, session.Value, time.Now())
	if err != nil {
		t.Fatalf("expected the session cookie to verify: %v", err)
	}
	if subject != "user-subject" {
		t.Fatalf("unexpected subject %q", subject)
	}

	clearedRecorder, clearedRequest := newTestContext(http.MethodGet, "/")
	auth.ClearSession(clearedRecorder, clearedRequest)

	var expired *http.Cookie
	for _, cookie := range clearedRecorder.Result().Cookies() {
		if cookie.Name == auth.Sessions.CookieName() {
			expired = cookie
		}
	}
	if expired == nil || expired.MaxAge != -1 {
		t.Fatalf("expected ClearSession to expire the cookie, got %+v", expired)
	}
}

func TestDefaultCookiePrefix_PrefersConfigOverClientID(t *testing.T) {
	if got := DefaultCookiePrefix(Config{CookiePrefix: "custom"}); got != "custom" {
		t.Fatalf("DefaultCookiePrefix() = %q, want %q", got, "custom")
	}

	if got := DefaultCookiePrefix(Config{ClientID: "My-App-Client"}); got != "myappclient" {
		t.Fatalf("DefaultCookiePrefix() = %q, want %q", got, "myappclient")
	}
}

func TestHandleCallback_RunsTheFullFlow(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	auth := New(func() Config { return config }, newHMACSessions(), "/auth/callback", "/login")

	state, err := RandomToken(stateTokenSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	verifier := "verifier"
	rec, req := newTestContext(http.MethodGet,
		server.URL+"/auth/callback?code=user-123&state="+state)
	req.AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: state + "|" + verifier + "|/jobs/1"})

	result, failure := auth.HandleCallback(rec, req)
	if failure != nil {
		t.Fatalf("unexpected failure: %v", failure.Cause)
	}
	if result.Subject != "user-123" || result.Redirect != "/jobs/1" {
		t.Fatalf("unexpected result: %+v", result)
	}

	var session *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.Sessions.CookieName() {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("expected a session cookie after the callback")
	}
	if subject, _, err := VerifyHMAC(testSessionKey, session.Value, time.Now()); err != nil || subject != "user-123" {
		t.Fatalf("expected a valid session for user-123, got %q: %v", subject, err)
	}
}

func TestHandleCallback_RejectsProviderReportedError(t *testing.T) {
	auth := newTestAuth(t)
	rec, req := newTestContext(http.MethodGet, "/auth/callback?error=access_denied")

	result, failure := auth.HandleCallback(rec, req)
	if result != nil || failure == nil || failure.Code != LoginErrorRejected {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
}

func TestHandleCallback_RejectsStateMismatch(t *testing.T) {
	auth := newTestAuth(t)
	rec, req := newTestContext(http.MethodGet, "/auth/callback?code=user-123&state=other")
	req.AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: "expected|verifier"})

	result, failure := auth.HandleCallback(rec, req)
	if result != nil || failure == nil || failure.Code != LoginErrorExpired {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
	if !errors.Is(failure.Cause, ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", failure.Cause)
	}
}

func TestHandleCallback_ClassifiesExchangeFailures(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	auth := New(func() Config { return config }, newHMACSessions(), "/auth/callback", "/login")

	rec, req := newTestContext(http.MethodGet,
		server.URL+"/auth/callback?code=no-id-token&state=any")
	req.AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: "any|verifier"})

	result, failure := auth.HandleCallback(rec, req)
	if result != nil || failure == nil || failure.Code != LoginErrorFailed {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
}

func TestHandleCallback_EnforcesAuthorizedSubjects(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	auth := New(func() Config { return config }, newHMACSessions(), "/auth/callback", "/login")
	auth.AuthorizeSubject = func(subject string) bool { return subject != "user-123" }

	state, err := RandomToken(stateTokenSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rec, req := newTestContext(http.MethodGet,
		server.URL+"/auth/callback?code=user-123&state="+state)
	req.AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: state + "|verifier"})

	result, failure := auth.HandleCallback(rec, req)
	if result != nil || failure == nil || failure.Code != LoginErrorRejected {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
	if !errors.Is(failure.Cause, ErrSubjectUnauthorized) {
		t.Fatalf("expected ErrSubjectUnauthorized, got %v", failure.Cause)
	}

	var session *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.Sessions.CookieName() {
			session = cookie
		}
	}
	if session != nil {
		t.Fatalf("expected no session cookie for an unauthorized subject, got %+v", session)
	}
}

func TestHandleCallback_ReportsSessionFailures(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	sessions := NewHMACSessions(HMACOptions{
		Prefix: "testapp",
		Settings: func() Config {
			broken := config
			broken.SessionKey = "too-short"

			return broken
		},
	})
	auth := New(func() Config { return config }, sessions, "/auth/callback", "/login")

	state, err := RandomToken(stateTokenSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rec, req := newTestContext(http.MethodGet,
		server.URL+"/auth/callback?code=user-123&state="+state)
	req.AddCookie(&http.Cookie{Name: auth.stateCookieName(), Value: state + "|verifier"})

	result, failure := auth.HandleCallback(rec, req)
	if result != nil || failure == nil || failure.Code != LoginErrorFailed {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
	if !errors.Is(failure.Cause, ErrInvalidSessionKey) {
		t.Fatalf("expected ErrInvalidSessionKey, got %v", failure.Cause)
	}
}

func TestExchange_ReturnsTheSubject(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	auth := New(func() Config { return config }, newHMACSessions(), "/auth/callback", "/login")

	_, req := newTestContext(http.MethodGet, server.URL+"/auth/callback?code=user-123")

	subject, err := auth.Exchange(req, "user-123", "verifier")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "user-123" {
		t.Fatalf("subject = %q, want %q", subject, "user-123")
	}
}

func TestMiddleware_AcceptsAuthenticatedRequest(t *testing.T) {
	auth := newTestAuth(t)
	cookie := auth.Sessions.CookieName() + "=" + SignHMAC(testSessionKey, "user-subject", time.Now().Add(time.Hour))

	rec := serveWithAuth(auth, "/", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for an authenticated request, got %d", rec.Code)
	}
}
