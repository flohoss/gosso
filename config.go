package gosso

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const MinSessionKeyLength = 32

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
	ErrInvalidIssuer     = errors.New("sso configuration error: issuer_url must be a valid absolute URL without a trailing slash")
	ErrMissingOIDCFields = errors.New("sso configuration error: issuer_url, client_id and client_secret are required when SSO is enabled")
)

func DefaultScopes() []string {
	return []string{"openid"}
}

func (c Config) Validate() error {
	if c.IssuerURL == "" || c.ClientID == "" || c.ClientSecret == "" {
		return ErrMissingOIDCFields
	}

	if _, err := url.Parse(c.IssuerURL); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	}
	if parsed, err := url.Parse(c.IssuerURL); err != nil || parsed.Host == "" || parsed.Scheme == "" || strings.HasSuffix(c.IssuerURL, "/") {
		return ErrInvalidIssuer
	}

	if c.AppURL != "" {
		if _, err := url.Parse(c.AppURL); err != nil {
			return fmt.Errorf("sso configuration error: app_url must be a valid URL: %w", err)
		}
	}

	return nil
}

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
