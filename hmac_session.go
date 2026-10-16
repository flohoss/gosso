package gosso

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

// DefaultSessionTTL is the session lifetime used when Config.SessionTTL is not positive.
const DefaultSessionTTL = 24 * time.Hour

// HMACOptions configures NewHMACSessions. CookieName takes precedence over Prefix.
type HMACOptions struct {
	Prefix     string
	CookieName string
	Settings   func() Config
}

// HMACSessions is a SessionManager backed by a signed, stateless cookie.
type HMACSessions struct {
	cookieName string
	settings   func() Config
}

// NewHMACSessions returns the cookie name from opts.CookieName, or opts.Prefix with "_session" appended.
func NewHMACSessions(opts HMACOptions) *HMACSessions {
	name := opts.CookieName
	if name == "" {
		name = opts.Prefix + "_session"
	}

	return &HMACSessions{
		cookieName: name,
		settings:   opts.Settings,
	}
}

// Start writes the signed session cookie for subject, expiring at expiresAt.
func (h *HMACSessions) Start(echoContext *echo.Context, subject string, expiresAt time.Time) error {
	if err := ValidateSessionKey(h.settings().SessionKey); err != nil {
		return err
	}

	echoContext.SetCookie(h.cookie(SignHMAC(h.settings().SessionKey, subject, expiresAt), 0, expiresAt))

	return nil
}

// Authenticate verifies the session cookie and refreshes it once half the TTL has passed.
func (h *HMACSessions) Authenticate(echoContext *echo.Context) (*User, error) {
	cookie, err := echoContext.Cookie(h.cookieName)
	if err != nil || cookie.Value == "" {
		return nil, ErrUnauthenticated
	}

	sessionKey := h.settings().SessionKey
	if err := ValidateSessionKey(sessionKey); err != nil {
		return nil, ErrUnauthenticated
	}

	subject, expiresAt, err := VerifyHMAC(sessionKey, cookie.Value, time.Now())
	if err != nil {
		return nil, ErrUnauthenticated
	}

	h.refresh(echoContext, subject, expiresAt)

	return &User{Subject: subject}, nil
}

// Clear expires the session cookie.
func (h *HMACSessions) Clear(echoContext *echo.Context) error {
	echoContext.SetCookie(h.cookie("", -1, time.Time{}))

	return nil
}

// CookieName returns the name of the session cookie.
func (h *HMACSessions) CookieName() string {
	return h.cookieName
}

func (h *HMACSessions) refresh(echoContext *echo.Context, subject string, expiresAt time.Time) {
	ttl := h.ttl()
	if ttl <= 0 {
		return
	}

	if time.Until(expiresAt) >= ttl/2 {
		return
	}

	renewed := time.Now().Add(ttl)
	echoContext.SetCookie(h.cookie(SignHMAC(h.settings().SessionKey, subject, renewed), 0, renewed))
}

func (h *HMACSessions) ttl() time.Duration {
	ttl := h.settings().SessionTTL
	if ttl <= 0 {
		return DefaultSessionTTL
	}

	return ttl
}

func (h *HMACSessions) cookie(value string, maxAge int, expires time.Time) *http.Cookie {
	return CookieOptions{Secure: h.secure}.Cookie(h.cookieName, value, maxAge, expires)
}

func (h *HMACSessions) secure() bool {
	return h.settings().CookieSecure
}
