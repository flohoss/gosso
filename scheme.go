package gosso

import (
	"net/http"
	"strings"
)

// User is the authenticated identity derived from a session.
type User struct {
	Subject string
}

// Scheme reports the request scheme without a framework: X-Forwarded-Proto wins, then TLS.
// Apps behind proxies that do not forward the original scheme should set Options.AppURL.
func Scheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}

	if r.TLS != nil {
		return "https"
	}

	return "http"
}

func (a *Auth) callbackURL(r *http.Request) string {
	if a.opts.AppURL != "" {
		return strings.TrimSuffix(a.opts.AppURL, "/") + CallbackRoute
	}

	return Scheme(r) + "://" + r.Host + CallbackRoute
}
