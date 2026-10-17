package gosso

import (
	"net/http"
	"time"
)

// DefaultSessionTTL is the session lifetime used when Config.SessionTTL is not positive.
const DefaultSessionTTL = 24 * time.Hour

// HMACOptions configures NewHMACSessions. When CookieName is empty the cookie is
// named from Prefix; when Prefix is empty too, it falls back to DefaultCookiePrefix
// of the settings, so the zero value still yields a usable cookie name.
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

// NewHMACSessions returns the cookie name from opts.CookieName, opts.Prefix, or the
// config-derived default prefix.
func NewHMACSessions(opts HMACOptions) *HMACSessions {
	name := opts.CookieName
	if name == "" {
		name = opts.Prefix + "_session"
	}
	if name == "_session" && opts.Settings != nil {
		name = DefaultCookiePrefix(opts.Settings()) + "_session"
	}

	return &HMACSessions{
		cookieName: name,
		settings:   opts.Settings,
	}
}

// Start writes the signed session cookie for subject, expiring at expiresAt.
func (h *HMACSessions) Start(w http.ResponseWriter, r *http.Request, subject string, expiresAt time.Time) error {
	if err := ValidateSessionKey(h.settings().SessionKey); err != nil {
		return err
	}

	http.SetCookie(w, h.cookie(SignHMAC(h.settings().SessionKey, subject, expiresAt), 0, expiresAt))

	return nil
}

// Authenticate verifies the session cookie and refreshes it once half the TTL has passed.
// Sessions are stateless by design: they cannot be revoked before their expiry, so back them
// with a custom SessionManager when immediate revocation matters.
func (h *HMACSessions) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	cookie, err := r.Cookie(h.cookieName)
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

	h.refresh(w, r, subject, expiresAt)

	return &User{Subject: subject}, nil
}

// Clear expires the session cookie.
func (h *HMACSessions) Clear(w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, h.cookie("", -1, time.Time{}))

	return nil
}

// CookieName returns the name of the session cookie.
func (h *HMACSessions) CookieName() string {
	return h.cookieName
}

func (h *HMACSessions) refresh(w http.ResponseWriter, r *http.Request, subject string, expiresAt time.Time) {
	ttl := h.settings().EffectiveSessionTTL()
	if time.Until(expiresAt) >= ttl/2 {
		return
	}

	renewed := time.Now().Add(ttl)
	http.SetCookie(w, h.cookie(SignHMAC(h.settings().SessionKey, subject, renewed), 0, renewed))
}

func (h *HMACSessions) cookie(value string, maxAge int, expires time.Time) *http.Cookie {
	return h.settings().CookieOptions().Cookie(h.cookieName, value, maxAge, expires)
}
