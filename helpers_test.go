package gosso

import (
	"net/http"
	"net/http/httptest"
	"time"
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

func newTestContext(method, target string) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()

	return rec, req
}

func serveWithAuth(auth *Auth, target string, cookie string) *httptest.ResponseRecorder {
	handler := auth.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}
