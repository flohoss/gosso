package gosso

import (
	"net/http"
	"time"
)

// newCookie builds the HttpOnly, SameSite=Lax cookies used for the state and the session.
// A negative maxAge expires the cookie.
func newCookie(name, value string, maxAge int, expires time.Time, secure bool) *http.Cookie {
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
