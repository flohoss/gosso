package gosso

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/labstack/echo/v5"
)

func testOptions() Options {
	return Options{
		Enabled:      true,
		IssuerURL:    "https://sso.example.com",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		SessionTTL:   time.Hour,
		LoginPath:    LoginPagePath,
	}
}

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sso.sqlite"))
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func newTestAuth(t *testing.T) *Auth {
	t.Helper()

	opts := testOptions()
	opts.DB = newTestDB(t)

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	return auth
}

func newTestContext(method, target string) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()

	return rec, req
}

func echoContext(rec *httptest.ResponseRecorder, req *http.Request) *echo.Context {
	router := echo.New()
	c := router.NewContext(req, rec)

	return c
}

func serveMiddleware(auth *Auth, rec *httptest.ResponseRecorder, req *http.Request) *httptest.ResponseRecorder {
	router := echo.New()
	router.Use(auth.Middleware())
	router.GET("/*", func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	router.ServeHTTP(rec, req)

	return rec
}

func stateCookieOf(t *testing.T, cookies []*http.Cookie, auth *Auth) *http.Cookie {
	t.Helper()

	return cookieNamed(t, cookies, auth.opts.stateCookieName())
}

func sessionCookieOf(t *testing.T, cookies []*http.Cookie, auth *Auth) *http.Cookie {
	t.Helper()

	return cookieNamed(t, cookies, auth.opts.CookieName)
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()

	var found *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == name {
			found = cookie
		}
	}

	return found
}

func startTestSession(t *testing.T, auth *Auth, subject string) *http.Cookie {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := auth.sessions.start(rec, req, subject); err != nil {
		t.Fatalf("failed to start a session: %v", err)
	}

	cookie := sessionCookieOf(t, rec.Result().Cookies(), auth)
	if cookie == nil {
		t.Fatal("expected a session cookie")
	}

	return cookie
}

func handleCallback(auth *Auth, target string) (*LoginResult, *LoginFailure) {
	req := httptest.NewRequest(http.MethodGet, target, nil)

	return auth.HandleCallback(echoContext(httptest.NewRecorder(), req))
}

func handleCallbackWithCookie(auth *Auth, target, stateValue string) (*LoginResult, *LoginFailure) {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.AddCookie(&http.Cookie{Name: auth.opts.stateCookieName(), Value: stateValue})

	return auth.HandleCallback(echoContext(httptest.NewRecorder(), req))
}

func callbackOf(t *testing.T, auth *Auth, server *httptest.Server, stateCookieValue, query string) (*httptest.ResponseRecorder, *LoginResult, *LoginFailure) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, server.URL+CallbackRoute+query, nil)
	req.AddCookie(&http.Cookie{Name: auth.opts.stateCookieName(), Value: stateCookieValue})

	result, failure := auth.HandleCallback(echoContext(rec, req))

	return rec, result, failure
}
