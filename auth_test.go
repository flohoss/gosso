package gosso

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/labstack/echo/v5"
	"golang.org/x/oauth2"
)

func newOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()

	oidcServer := &oidctest.Server{}
	server := httptest.NewServer(oidcServer)
	t.Cleanup(server.Close)
	oidcServer.SetIssuer(server.URL)

	return server
}

func TestNew_DisabledAuthenticatesNothingAndReturns404(t *testing.T) {
	auth, err := New(Options{DB: newTestDB(t)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if r, req := newTestContext(http.MethodGet, "/anything"); serveMiddleware(auth, r, req).Code != http.StatusOK {
		t.Fatal("expected open access while disabled")
	}
}

func TestStartLogin_RedirectsToProviderWithStateCookie(t *testing.T) {
	server := newOIDCServer(t)
	auth := newTestAuthForProvider(t, server)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)

	if err := auth.StartLogin(echoContext(rec, req), "/after/login"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

	stateCookie := stateCookieOf(t, rec.Result().Cookies(), auth)
	if stateCookie.MaxAge != int(stateCookieTTL.Seconds()) {
		t.Fatalf("expected a short-lived state cookie, got %d", stateCookie.MaxAge)
	}
	if !stateCookie.HttpOnly {
		t.Fatal("expected the state cookie to be HttpOnly")
	}

	parts := strings.Split(stateCookie.Value, stateSeparator)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "/after/login" {
		t.Fatalf("expected state|verifier|redirect, got %q", stateCookie.Value)
	}

	// oauth2 appends the redirect_uri at the front, producing
	// auth?redirect_uri=...&client_id=...; only param presence and values matter.
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse the provider redirect %q: %v", location, err)
	}

	query := u.Query()
	if query.Get("client_id") != testOptions().ClientID {
		t.Errorf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "http://example.com"+CallbackRoute {
		t.Errorf("redirect_uri = %q", query.Get("redirect_uri"))
	}
	if query.Get("response_type") != "code" {
		t.Errorf("response_type = %q", query.Get("response_type"))
	}
	if query.Get("scope") != "openid" {
		t.Errorf("scope = %q", query.Get("scope"))
	}
	if query.Get("state") != parts[0] {
		t.Errorf("state = %q, want the cookie state", query.Get("state"))
	}
	if query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(parts[1]) {
		t.Errorf("code_challenge = %q, want the S256 challenge of the cookie verifier", query.Get("code_challenge"))
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", query.Get("code_challenge_method"))
	}
}

func TestStartLogin_OmitsTheRedirectSegmentWithoutATarget(t *testing.T) {
	server := newOIDCServer(t)
	auth := newTestAuthForProvider(t, server)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)

	if err := auth.StartLogin(echoContext(rec, req), ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := strings.Count(stateCookieOf(t, rec.Result().Cookies(), auth).Value, stateSeparator); got != 1 {
		t.Fatalf("expected state|verifier only, got %d separators", got)
	}
}

func TestStartLogin_RejectsInvalidOptions(t *testing.T) {
	auth := newTestAuth(t)
	auth.opts.ClientSecret = ""

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)

	if err := auth.StartLogin(echoContext(rec, req), "/"); !errors.Is(err, ErrMissingOIDCFields) {
		t.Fatalf("expected ErrMissingOIDCFields, got %v", err)
	}
}

func TestStartLogin_FailsWhenProviderUnavailable(t *testing.T) {
	auth := newTestAuth(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)

	if err := auth.StartLogin(echoContext(rec, req), "/"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
}

// The handoff target has to survive the provider round trip inside the state
// cookie and be rejected unless it is a site-relative path.
func TestStartLogin_SanitizesTheRedirectTarget(t *testing.T) {
	server := newOIDCServer(t)
	auth := newTestAuthForProvider(t, server)

	for raw, want := range map[string]string{
		"https://evil.example.com": "/",
		"/jobs/1":                  "/jobs/1",
		"/x\r\nSet-Cookie: p=1":    "/",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)

		if err := auth.StartLogin(echoContext(rec, req), raw); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		value := stateCookieOf(t, rec.Result().Cookies(), auth).Value
		parts := strings.Split(value, stateSeparator)
		got := "/"
		if len(parts) > 2 {
			got = parts[2]
		}
		if got != want {
			t.Errorf("StartLogin(%q) stored %q, want %q", raw, got, want)
		}
	}
}

func TestMiddleware_RedirectsUnauthenticatedToLoginPath(t *testing.T) {
	auth := newTestAuth(t)

	rec := serveMiddleware(auth, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("expected a redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != LoginPagePath {
		t.Fatalf("expected a redirect to %q, got %q", LoginPagePath, location)
	}
}

func TestMiddleware_WithoutLoginPathReturnsUnauthorized(t *testing.T) {
	opts := testOptions()
	opts.LoginPath = ""
	opts.DB = newTestDB(t)

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec := serveMiddleware(auth, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMiddleware_AcceptsAnAuthenticatedRequest(t *testing.T) {
	auth := newTestAuth(t)

	cookie := startTestSession(t, auth, "user-subject")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	if got := serveMiddleware(auth, httptest.NewRecorder(), req).Code; got != http.StatusOK {
		t.Fatalf("expected 200 for an authenticated request, got %d", got)
	}
}

func TestMiddleware_PassesThroughWhenDisabled(t *testing.T) {
	opts := Options{DB: newTestDB(t)}

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := serveMiddleware(auth, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)).Code; got != http.StatusOK {
		t.Fatalf("expected 200 while disabled, got %d", got)
	}
}

func TestHandleCallback_RejectsProviderReportedError(t *testing.T) {
	auth := newTestAuth(t)

	result, failure := handleCallback(auth, "/api/auth/callback?error=access_denied")
	if result != nil || failure == nil || failure.Code != LoginErrorRejected {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
}

func TestHandleCallback_RejectsStateMismatch(t *testing.T) {
	auth := newTestAuth(t)

	result, failure := handleCallbackWithCookie(auth, "/api/auth/callback?code=user-123&state=other", "expected|verifier")
	if result != nil || failure == nil || failure.Code != LoginErrorExpired {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
	if !errors.Is(failure.Cause, ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", failure.Cause)
	}
}

func TestHandleCallback_ClassifiesExchangeFailures(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	result, failure := handleCallbackWithCookie(auth,
		server.URL+"/api/auth/callback?code=no-id-token&state=any", "any|verifier")
	if result != nil || failure == nil || failure.Code != LoginErrorFailed {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
}

func TestHandleCallback_StartsTheSession(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	rec, result, failure := callbackOf(t, auth, server,
		"state-value|verifier|/jobs/1", "?code=user-123&state=state-value")
	if failure != nil {
		t.Fatalf("unexpected failure: %v", failure.Cause)
	}
	if result.Subject != "user-123" || result.Redirect != "/jobs/1" {
		t.Fatalf("unexpected result: %+v", result)
	}

	session := sessionCookieOf(t, rec.Result().Cookies(), auth)
	if session == nil {
		t.Fatal("expected a session cookie after the callback")
	}

	authenticated := httptest.NewRequest(http.MethodGet, "/", nil)
	authenticated.AddCookie(session)
	if user, err := auth.Authenticate(echoContext(httptest.NewRecorder(), authenticated)); err != nil || user.Subject != "user-123" {
		t.Fatalf("expected a valid stored session, got %v", err)
	}
}

func TestHandleCallback_PreservesSessionWhenProviderResolvesLate(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	rec, result, failure := callbackOf(t, auth, server,
		"state-value|verifier", "?code=user-123&state=state-value")
	if failure != nil {
		t.Fatalf("unexpected failure: %v", failure.Cause)
	}
	if result.Redirect != "/" {
		t.Fatalf("Redirect = %q, want the fallback", result.Redirect)
	}

	session := sessionCookieOf(t, rec.Result().Cookies(), auth)
	if session == nil || session.MaxAge != 0 {
		t.Fatalf("expected a persistent session cookie, got %+v", session)
	}
}

func TestHandleCallback_ReportsSessionFailures(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	_ = auth.sessions.db.Close()

	_, result, failure := callbackOf(t, auth, server,
		"state-value|verifier", "?code=user-123&state=state-value")
	if result != nil || failure == nil || failure.Code != LoginErrorFailed {
		t.Fatalf("unexpected failure: %+v, %+v", result, failure)
	}
}

func TestAuthenticate_RejectsMissingOrUnknownSession(t *testing.T) {
	auth := newTestAuth(t)

	withoutCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := auth.Authenticate(echoContext(httptest.NewRecorder(), withoutCookie)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated without a cookie, got %v", err)
	}

	unknown := httptest.NewRequest(http.MethodGet, "/", nil)
	unknown.AddCookie(&http.Cookie{Name: auth.opts.CookieName, Value: "unknown"})
	if _, err := auth.Authenticate(echoContext(httptest.NewRecorder(), unknown)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated for an unknown session, got %v", err)
	}
}

func TestClearSession_RevokesAndExpiresTheCookie(t *testing.T) {
	auth := newTestAuth(t)
	cookie := startTestSession(t, auth, "user-subject")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	auth.ClearSession(echoContext(rec, req))

	if _, err := auth.Authenticate(echoContext(httptest.NewRecorder(), req)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected the session to be revoked, got %v", err)
	}

	expired := sessionCookieOf(t, rec.Result().Cookies(), auth)
	if expired == nil || expired.MaxAge != -1 {
		t.Fatalf("expected ClearSession to expire the cookie, got %+v", expired)
	}
}

func TestCleanup_RemovesExpiredSessions(t *testing.T) {
	auth := newTestAuth(t)
	cookie := startTestSession(t, auth, "user-subject")
	expireSession(t, auth, cookie)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	auth.Cleanup(ctx)

	if count := sessionCount(t, auth); count != 0 {
		t.Fatalf("%d expired sessions survived the cleanup", count)
	}
}

// synctest fakes the clock, so the hourly ticker fires without waiting.
func TestCleanup_DeletesExpiredSessionsOnEveryTick(t *testing.T) {
	auth := newTestAuth(t)
	cookie := startTestSession(t, auth, "user-subject")
	expireSession(t, auth, cookie)

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			auth.Cleanup(ctx)
		}()

		time.Sleep(cleanupInterval)
		synctest.Wait()

		cancel()
		<-done
	})

	if count := sessionCount(t, auth); count != 0 {
		t.Fatalf("%d sessions survived the cleanup tick", count)
	}
}

func expireSession(t *testing.T, auth *Auth, cookie *http.Cookie) {
	t.Helper()

	if _, err := auth.sessions.db.ExecContext(t.Context(),
		`UPDATE sso_sessions SET expires_at = 0 WHERE jti = ?`, cookie.Value); err != nil {
		t.Fatalf("failed to expire the session: %v", err)
	}
}

func sessionCount(t *testing.T, auth *Auth) int {
	t.Helper()

	var count int
	if err := auth.sessions.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sso_sessions`).Scan(&count); err != nil {
		t.Fatalf("failed to count sessions: %v", err)
	}

	return count
}

func TestHandleCallback_RejectsMalformedStateCookies(t *testing.T) {
	auth := newTestAuth(t)

	for _, value := range []string{"", "only", "|verifier", "state|"} {
		_, _, _, err := auth.consumeLoginState(httptest.NewRecorder(), requestWithStateCookie(t, auth, value))
		if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("expected ErrUnauthenticated for the state cookie %q, got %v", value, err)
		}
	}
}

func requestWithStateCookie(t *testing.T, auth *Auth, value string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, CallbackRoute, nil)
	req.AddCookie(&http.Cookie{Name: auth.opts.stateCookieName(), Value: value})

	return req
}
