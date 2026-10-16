package gosso

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

// User is the authenticated identity derived from a session.
type User struct {
	Subject string
}

// SessionManager stores and reads the session behind a request so apps can swap in their own store.
type SessionManager interface {
	Start(echoContext *echo.Context, subject string, expiresAt time.Time) error
	Authenticate(echoContext *echo.Context) (*User, error)
	Clear(echoContext *echo.Context) error
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
