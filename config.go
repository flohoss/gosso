package gosso

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// MinSessionKeyLength is the shortest accepted signing key for HMACSessions.
const MinSessionKeyLength = 32

// Config holds the OpenID Connect settings shared by all apps using this package.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	SessionKey   string
	SessionTTL   time.Duration
	CookieSecure bool
	AppURL       string
	Scopes       []string
	CookiePrefix string
	Enabled      bool
}

var (
	// ErrInvalidIssuer is returned when IssuerURL is not an absolute URL or has a trailing slash.
	ErrInvalidIssuer = errors.New("sso configuration error: issuer_url must be a valid absolute URL without a trailing slash")
	// ErrMissingOIDCFields is returned when a required credential is empty while SSO is enabled.
	ErrMissingOIDCFields = errors.New("sso configuration error: issuer_url, client_id and client_secret are required when SSO is enabled")
)

// DefaultScopes returns the scopes requested when Config.Scopes is empty.
func DefaultScopes() []string {
	return []string{"openid"}
}

// Validate reports whether the config carries usable issuer credentials and, when set, a parsable AppURL.
func (c Config) Validate() error {
	if c.IssuerURL == "" || c.ClientID == "" || c.ClientSecret == "" {
		return ErrMissingOIDCFields
	}

	parsed, err := url.Parse(c.IssuerURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" || strings.HasSuffix(c.IssuerURL, "/") {
		return ErrInvalidIssuer
	}

	if c.AppURL != "" {
		if _, err := url.Parse(c.AppURL); err != nil {
			return fmt.Errorf("sso configuration error: app_url must be a valid URL: %w", err)
		}
	}

	if c.SessionKey != "" {
		if err := ValidateSessionKey(c.SessionKey); err != nil {
			return fmt.Errorf("sso configuration error: %w", err)
		}
	}

	return nil
}

// EffectiveSessionTTL returns SessionTTL, falling back to DefaultSessionTTL when it is not positive.
func (c Config) EffectiveSessionTTL() time.Duration {
	if c.SessionTTL <= 0 {
		return DefaultSessionTTL
	}

	return c.SessionTTL
}

// CookieOptions returns the shared cookie attributes for this config.
func (c Config) CookieOptions() CookieOptions {
	secure := c.CookieSecure

	return CookieOptions{Secure: func() bool { return secure }}
}

// WithDefaults returns a copy with SessionTTL and Scopes filled in when they are empty.
func (c Config) WithDefaults() Config {
	filled := c

	if filled.SessionTTL <= 0 {
		filled.SessionTTL = DefaultSessionTTL
	}
	if len(filled.Scopes) == 0 {
		filled.Scopes = DefaultScopes()
	}

	return filled
}
