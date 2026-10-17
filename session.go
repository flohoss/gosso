package gosso

import (
	"net/http"
	"time"
)

// User is the authenticated identity derived from a session.
type User struct {
	Subject string
}

// SessionManager stores and reads the session behind a request so apps can swap in their own store.
type SessionManager interface {
	Start(w http.ResponseWriter, r *http.Request, subject string, expiresAt time.Time) error
	Authenticate(w http.ResponseWriter, r *http.Request) (*User, error)
	Clear(w http.ResponseWriter, r *http.Request) error
	CookieName() string
}

// CookieOptions builds the HttpOnly, SameSite=Lax cookies shared by the session implementations.
type CookieOptions struct {
	Secure func() bool
}

// Cookie returns the cookie with the shared attributes applied. A negative maxAge expires it.
func (o CookieOptions) Cookie(name, value string, maxAge int, expires time.Time) *http.Cookie {
	secure := false
	if o.Secure != nil {
		secure = o.Secure()
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// Scheme reports the request scheme without a framework: X-Forwarded-Proto wins, then TLS.
// Apps behind proxies that do not forward the original scheme should set Config.AppURL.
func Scheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}

	if r.TLS != nil {
		return "https"
	}

	return "http"
}
