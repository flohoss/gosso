package gosso

import (
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/labstack/echo/v5"
)

const testSessionKey = "a-sufficiently-long-session-signing-key"

func testConfig() Config {
	return Config{
		Enabled:      true,
		IssuerURL:    "https://sso.example.com",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		SessionKey:   testSessionKey,
		SessionTTL:   time.Hour,
	}
}

func newTestContext(method, target string) (*echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()

	return e.NewContext(req, rec), rec
}

func serveWithAuth(auth *Auth, target string, cookie string) *httptest.ResponseRecorder {
	e := echo.New()
	e.Use(auth.Middleware())
	e.GET(target, func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != "" {
		req.Header.Set(echo.HeaderCookie, cookie)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	return rec
}
