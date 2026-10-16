package gosso

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

type User struct {
	Subject string
}

type SessionManager interface {
	Start(echoContext *echo.Context, subject string, expiresAt time.Time) error
	Authenticate(echoContext *echo.Context) (*User, error)
	Clear(echoContext *echo.Context) error
	CookieName() string
}

type CookieOptions struct {
	Secure func() bool
}

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
