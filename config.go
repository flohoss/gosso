package gosso

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultSessionTTL is the session lifetime used when Options.SessionTTL is not positive.
	DefaultSessionTTL = 24 * time.Hour

	defaultCookieSuffix = "_session"
	defaultStateSuffix  = "_oidc_state"
)

// Options holds the OpenID Connect settings and dependencies of a single app.
type Options struct {
	// Enabled switches the whole auth surface on. A disabled instance answers 404
	// on the lifecycle routes and lets every request through.
	Enabled bool

	IssuerURL    string
	ClientID     string
	ClientSecret string

	// SessionTTL bounds a session; DefaultSessionTTL applies when it is not positive.
	SessionTTL time.Duration

	// CookieSecure marks the cookies as HTTPS-only.
	CookieSecure bool

	// CookiePrefix prefixes the state cookie and derives the session cookie name.
	// It defaults to the sanitized ClientID.
	CookiePrefix string

	// CookieName overrides the session cookie name. It defaults to CookiePrefix + "_session".
	CookieName string

	// AppURL is the externally reachable base URL. When empty the callback URL is
	// derived from the request, which needs a proxy that forwards the scheme.
	AppURL string

	// LoginPath is where Middleware redirects unauthenticated requests. When empty
	// they are answered with 401 instead, which suits JSON APIs.
	LoginPath string

	// Scopes defaults to ["openid"].
	Scopes []string

	// DB stores the sessions. It is created and cleaned up by this package.
	DB *sql.DB
}

var (
	// ErrInvalidIssuer is returned when IssuerURL is not an absolute URL or has a trailing slash.
	ErrInvalidIssuer = errors.New("sso configuration error: issuer_url must be a valid absolute URL without a trailing slash")
	// ErrMissingOIDCFields is returned when a required credential is empty while SSO is enabled.
	ErrMissingOIDCFields = errors.New("sso configuration error: issuer_url, client_id and client_secret are required when SSO is enabled")
	// ErrMissingDatabase is returned when no database was supplied for the session store.
	ErrMissingDatabase = errors.New("sso configuration error: a database is required to store sessions")
	// ErrInvalidAppURL is returned when AppURL is set but not parsable.
	ErrInvalidAppURL = errors.New("sso configuration error: app_url must be a valid URL")
)

// Validate reports whether the options carry usable issuer credentials and a parsable AppURL.
func (o Options) Validate() error {
	if o.IssuerURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return ErrMissingOIDCFields
	}

	parsed, err := url.Parse(o.IssuerURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" || strings.HasSuffix(o.IssuerURL, "/") {
		return ErrInvalidIssuer
	}

	if o.AppURL != "" {
		if _, err := url.Parse(o.AppURL); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidAppURL, err)
		}
	}

	return nil
}

// LoginPageURL returns the login page with the error code as query when one is set.
func LoginPageURL(code LoginError) string {
	if code == "" {
		return LoginPagePath
	}

	return LoginPagePath + "?" + LoginQueryParam + "=" + string(code)
}

func (o Options) withDefaults() Options {
	filled := o

	if filled.SessionTTL <= 0 {
		filled.SessionTTL = DefaultSessionTTL
	}
	if len(filled.Scopes) == 0 {
		filled.Scopes = []string{"openid"}
	}
	if filled.CookiePrefix == "" {
		filled.CookiePrefix = defaultCookiePrefix(filled.ClientID)
	}
	if filled.CookieName == "" {
		filled.CookieName = filled.CookiePrefix + defaultCookieSuffix
	}

	return filled
}

func defaultCookiePrefix(clientID string) string {
	return strings.ToLower(strings.ReplaceAll(clientID, "-", ""))
}

func (o Options) stateCookieName() string {
	return o.CookiePrefix + defaultStateSuffix
}
