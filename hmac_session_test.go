package gosso

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
)

func newHMACSessions() *HMACSessions {
	return NewHMACSessions(HMACOptions{
		Prefix:   "testapp",
		Settings: func() Config { return testConfig() },
	})
}

func TestHMACSessions_StartSetsSignedCookie(t *testing.T) {
	sessions := newHMACSessions()
	echoContext, rec := newTestContext(http.MethodGet, "/")
	expiresAt := time.Now().Add(time.Hour)

	if err := sessions.Start(echoContext, "user-subject", expiresAt); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sessionCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessions.CookieName() {
			sessionCookie = cookie
		}
	}

	if sessionCookie == nil {
		t.Fatal("expected a session cookie to be set")
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("expected the session cookie to be HttpOnly")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite Lax, got %v", sessionCookie.SameSite)
	}

	subject, _, err := VerifyHMAC(testSessionKey, sessionCookie.Value, time.Now())
	if err != nil {
		t.Fatalf("expected the cookie value to verify: %v", err)
	}
	if subject != "user-subject" {
		t.Fatalf("unexpected subject %q", subject)
	}
}

func TestHMACSessions_AuthenticateRoundTrips(t *testing.T) {
	sessions := newHMACSessions()

	rec := httptest.NewRecorder()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderCookie, sessions.CookieName()+"="+SignHMAC(testSessionKey, "user-subject", time.Now().Add(time.Hour)))
	c := e.NewContext(req, rec)

	user, err := sessions.Authenticate(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Subject != "user-subject" {
		t.Fatalf("unexpected subject %q", user.Subject)
	}
}

func TestHMACSessions_AuthenticateRejectsGarbage(t *testing.T) {
	sessions := newHMACSessions()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderCookie, sessions.CookieName()+"=tampered")
	c := e.NewContext(req, httptest.NewRecorder())

	if _, err := sessions.Authenticate(c); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestHMACSessions_ClearExpiresCookie(t *testing.T) {
	sessions := newHMACSessions()
	echoContext, rec := newTestContext(http.MethodGet, "/")

	if err := sessions.Clear(echoContext); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var cleared *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessions.CookieName() {
			cleared = cookie
		}
	}
	if cleared == nil || cleared.MaxAge != -1 {
		t.Fatalf("expected an expiring cookie, got %+v", cleared)
	}
}

func TestHMACSessions_RefreshesPastHalfTTL(t *testing.T) {
	sessions := newHMACSessions()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	oldExpiry := time.Now().Add(30 * time.Minute)
	req.Header.Set(echo.HeaderCookie, sessions.CookieName()+"="+SignHMAC(testSessionKey, "user-subject", oldExpiry))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if _, err := sessions.Authenticate(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var renewed *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessions.CookieName() {
			renewed = cookie
		}
	}
	if renewed == nil {
		t.Fatal("expected a renewed session cookie past half the TTL")
	}
	if _, expiry, err := VerifyHMAC(testSessionKey, renewed.Value, time.Now()); err != nil || expiry.Before(time.Now().Add(55*time.Minute)) {
		t.Fatalf("expected the renewed cookie to extend the session: %v", err)
	}
}

func TestHMACSessions_DoesNotRefreshEarly(t *testing.T) {
	sessions := newHMACSessions()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	freshExpiry := time.Now().Add(time.Hour)
	req.Header.Set(echo.HeaderCookie, sessions.CookieName()+"="+SignHMAC(testSessionKey, "user-subject", freshExpiry))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if _, err := sessions.Authenticate(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, cookie := range rec.Result().Cookies() {
		if strings.Contains(cookie.Value, ".") && cookie.Name == sessions.CookieName() {
			t.Fatal("expected no renewed session cookie within half the TTL")
		}
	}
}
