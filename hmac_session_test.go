package gosso

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newHMACSessions() *HMACSessions {
	return NewHMACSessions(HMACOptions{
		Prefix:   "testapp",
		Settings: func() Config { return testConfig() },
	})
}

func TestHMACSessions_StartSetsSignedCookie(t *testing.T) {
	sessions := newHMACSessions()
	rec, req := newTestContext(http.MethodGet, "/")
	expiresAt := time.Now().Add(time.Hour)

	if err := sessions.Start(rec, req, "user-subject", expiresAt); err != nil {
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
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", sessions.CookieName()+"="+SignHMAC(testSessionKey, "user-subject", time.Now().Add(time.Hour)))

	user, err := sessions.Authenticate(rec, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Subject != "user-subject" {
		t.Fatalf("unexpected subject %q", user.Subject)
	}
}

func TestHMACSessions_AuthenticateRejectsGarbage(t *testing.T) {
	sessions := newHMACSessions()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", sessions.CookieName()+"=tampered")

	if _, err := sessions.Authenticate(httptest.NewRecorder(), req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestHMACSessions_ClearExpiresCookie(t *testing.T) {
	sessions := newHMACSessions()
	rec, req := newTestContext(http.MethodGet, "/")

	if err := sessions.Clear(rec, req); err != nil {
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	oldExpiry := time.Now().Add(30 * time.Minute)
	req.Header.Set("Cookie", sessions.CookieName()+"="+SignHMAC(testSessionKey, "user-subject", oldExpiry))
	rec := httptest.NewRecorder()

	if _, err := sessions.Authenticate(rec, req); err != nil {
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

func TestHMACSessions_RefreshesUsingDefaultTTLWhenUnset(t *testing.T) {
	config := testConfig()
	config.SessionTTL = 0
	sessions := NewHMACSessions(HMACOptions{Prefix: "testapp", Settings: func() Config { return config }})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", sessions.CookieName()+"="+SignHMAC(testSessionKey, "user-subject", time.Now().Add(30*time.Minute)))
	rec := httptest.NewRecorder()

	if _, err := sessions.Authenticate(rec, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var renewed *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessions.CookieName() {
			renewed = cookie
		}
	}
	if renewed == nil {
		t.Fatal("expected a refresh against the default TTL")
	}
	if _, expiry, err := VerifyHMAC(testSessionKey, renewed.Value, time.Now()); err != nil || expiry.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("expected the refreshed expiry to follow the default TTL: %v", err)
	}
}

func TestHMACSessions_DoesNotRefreshEarly(t *testing.T) {
	sessions := newHMACSessions()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	freshExpiry := time.Now().Add(time.Hour)
	req.Header.Set("Cookie", sessions.CookieName()+"="+SignHMAC(testSessionKey, "user-subject", freshExpiry))
	rec := httptest.NewRecorder()

	if _, err := sessions.Authenticate(rec, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, cookie := range rec.Result().Cookies() {
		if strings.Contains(cookie.Value, ".") && cookie.Name == sessions.CookieName() {
			t.Fatal("expected no renewed session cookie within half the TTL")
		}
	}
}

// A short signing key must never produce a session: Start rejects it loudly so
// a misconfigured deployment fails at the first login instead of issuing
// forgeable cookies.
func TestHMACSessions_StartRejectsShortKey(t *testing.T) {
	config := testConfig()
	config.SessionKey = "too-short"

	sessions := NewHMACSessions(HMACOptions{Prefix: "testapp", Settings: func() Config { return config }})
	rec, req := newTestContext(http.MethodGet, "/")

	if err := sessions.Start(rec, req, "user-subject", time.Now().Add(time.Hour)); !errors.Is(err, ErrInvalidSessionKey) {
		t.Fatalf("expected ErrInvalidSessionKey, got %v", err)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("expected no session cookie for a rejected key")
	}
}

// A valid-looking cookie signed with a now-rejected key must not authenticate.
func TestHMACSessions_AuthenticateRejectsShortKey(t *testing.T) {
	config := testConfig()
	config.SessionKey = "too-short"

	sessions := NewHMACSessions(HMACOptions{Prefix: "testapp", Settings: func() Config { return config }})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", sessions.CookieName()+"="+SignHMAC("too-short", "user-subject", time.Now().Add(time.Hour)))

	if _, err := sessions.Authenticate(httptest.NewRecorder(), req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}
