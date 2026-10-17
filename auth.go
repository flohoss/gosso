package gosso

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/oauth2"
)

const (
	stateCookieTTL = 10 * time.Minute
	stateSeparator = "|"
)

// Auth runs the Echo v5 login lifecycle and the session middleware for a single app.
type Auth struct {
	Sessions SessionManager

	Settings     func() Config
	CallbackPath string
	LoginPath    string

	// AuthorizeSubject optionally gates logins: when it returns false for the verified
	// subject, the callback fails with LoginErrorRejected before a session is started.
	AuthorizeSubject func(subject string) bool

	provider *Provider
}

// LoginResult reports a successful OIDC callback.
type LoginResult struct {
	// Subject is the verified subject of the id_token.
	Subject string
	// Redirect is the sanitized, same-origin path requested before the login.
	Redirect string
}

// LoginFailure reports why an OIDC callback failed.
type LoginFailure struct {
	// Code is the stable LoginError code for the login page redirect.
	Code LoginError
	// Cause is the underlying error, safe to log but not to expose to the browser.
	Cause error
}

// New wires an Auth to settings and a session store. Enabled settings warm provider discovery in the background.
func New(settings func() Config, sessions SessionManager, callbackPath, loginPath string) *Auth {
	auth := &Auth{
		Sessions:     sessions,
		Settings:     settings,
		CallbackPath: callbackPath,
		LoginPath:    loginPath,
		provider:     NewProvider(settings),
	}

	if auth.Enabled() {
		auth.provider.Warm()
	}

	return auth
}

// Enabled reports whether SSO is switched on, tolerating a nil receiver.
func (a *Auth) Enabled() bool {
	if a == nil {
		return false
	}

	return a.Settings().Enabled
}

// StartLogin writes the state cookie and redirects the browser to the provider.
func (a *Auth) StartLogin(echoContext *echo.Context, redirect string) error {
	config := a.Settings()
	if err := config.Validate(); err != nil {
		return err
	}

	login, err := a.provider.Login(config, a.callbackURL(echoContext))
	if err != nil {
		return err
	}

	state, err := RandomToken(stateTokenSize)
	if err != nil {
		return err
	}

	verifier := oauth2.GenerateVerifier()

	value := state + stateSeparator + verifier
	if redirect = SanitizeRedirect(redirect); redirect != "/" {
		value += stateSeparator + redirect
	}

	a.clearLoginState(echoContext)
	echoContext.SetCookie(a.stateCookie(value, int(stateCookieTTL.Seconds()), time.Time{}))

	echoContext.Redirect(http.StatusFound, login.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)))

	return nil
}

// ConsumeLoginState validates and clears the state cookie and returns the state, PKCE verifier and redirect target.
// The cookie is cleared before it is read on purpose: one-shot semantics come from the response
// expiring it, while the request copy stays readable for this handler.
func (a *Auth) ConsumeLoginState(echoContext *echo.Context) (state, verifier, redirect string, err error) {
	a.clearLoginState(echoContext)

	cookie, cookieErr := echoContext.Cookie(a.stateCookieName())
	if cookieErr != nil {
		return "", "", "", ErrUnauthenticated
	}

	parts := strings.Split(cookie.Value, stateSeparator)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", ErrUnauthenticated
	}

	state, verifier, redirect = parts[0], parts[1], "/"
	if len(parts) > 2 && parts[2] != "" {
		redirect = SanitizeRedirect(parts[2])
	}

	return state, verifier, redirect, nil
}

// Exchange redeems the authorization code and returns the verified subject of the id_token.
func (a *Auth) Exchange(echoContext *echo.Context, code, verifier string) (string, error) {
	config := a.Settings()

	return a.provider.Exchange(echoContext.Request().Context(), config, code, verifier, a.callbackURL(echoContext))
}

// StartSession stores a session for subject through the configured SessionManager.
func (a *Auth) StartSession(echoContext *echo.Context, subject string) error {
	return a.Sessions.Start(echoContext, subject, time.Now().Add(a.SessionTTL()))
}

// Authenticate resolves the current user from the session store.
func (a *Auth) Authenticate(echoContext *echo.Context) (*User, error) {
	return a.Sessions.Authenticate(echoContext)
}

// ClearSession removes the local session, without contacting the provider.
func (a *Auth) ClearSession(echoContext *echo.Context) {
	a.Sessions.Clear(echoContext)
}

// SessionTTL returns the configured session lifetime, falling back to DefaultSessionTTL.
func (a *Auth) SessionTTL() time.Duration {
	return a.Settings().EffectiveSessionTTL()
}

// HandleCallback finishes the OIDC login for a callback request: it rejects provider-reported
// errors, consumes and checks the state cookie, exchanges the code, applies AuthorizeSubject
// and starts the session. It returns the login result or a classified failure for the login
// page redirect.
func (a *Auth) HandleCallback(echoContext *echo.Context) (*LoginResult, *LoginFailure) {
	if raw := echoContext.QueryParam("error"); raw != "" {
		return nil, &LoginFailure{Code: LoginErrorRejected, Cause: fmt.Errorf("provider reported %q", raw)}
	}

	state, verifier, redirect, err := a.ConsumeLoginState(echoContext)
	if err != nil {
		return nil, &LoginFailure{Code: LoginErrorExpired, Cause: err}
	}

	if echoContext.QueryParam("state") != state {
		return nil, &LoginFailure{Code: LoginErrorExpired, Cause: ErrStateMismatch}
	}

	subject, err := a.Exchange(echoContext, echoContext.QueryParam("code"), verifier)
	if err != nil {
		return nil, &LoginFailure{Code: ClassifyLoginError(err), Cause: err}
	}

	if a.AuthorizeSubject != nil && !a.AuthorizeSubject(subject) {
		return nil, &LoginFailure{Code: LoginErrorRejected, Cause: ErrSubjectUnauthorized}
	}

	if err := a.StartSession(echoContext, subject); err != nil {
		return nil, &LoginFailure{Code: LoginErrorFailed, Cause: err}
	}

	if redirect == "" {
		redirect = "/"
	}

	return &LoginResult{Subject: subject, Redirect: redirect}, nil
}

// Middleware redirects unauthenticated requests to LoginPath, or answers 401 when no login path is set.
func (a *Auth) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if !a.Enabled() {
				return next(c)
			}

			if _, err := a.Authenticate(c); err != nil {
				if a.LoginPath == "" {
					return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
				}

				return c.Redirect(http.StatusFound, a.LoginPath)
			}

			return next(c)
		}
	}
}

func (a *Auth) stateCookieName() string {
	return a.prefix() + "_oidc_state"
}

func (a *Auth) prefix() string {
	return DefaultCookiePrefix(a.Settings())
}

// DefaultCookiePrefix returns the cookie prefix from the config, or one derived from the ClientID.
func DefaultCookiePrefix(config Config) string {
	if config.CookiePrefix != "" {
		return config.CookiePrefix
	}

	return strings.ToLower(strings.ReplaceAll(config.ClientID, "-", ""))
}

func (a *Auth) stateCookie(value string, maxAge int, expires time.Time) *http.Cookie {
	return CookieOptions{Secure: a.cookieSecure}.Cookie(a.stateCookieName(), value, maxAge, expires)
}

func (a *Auth) clearLoginState(echoContext *echo.Context) {
	echoContext.SetCookie(a.stateCookie("", -1, time.Time{}))
}

func (a *Auth) cookieSecure() bool {
	return a.Settings().CookieSecure
}

// CallbackURL returns the redirect URI registered with the provider for this request.
func (a *Auth) CallbackURL(c *echo.Context) string {
	return a.callbackURL(c)
}

// Resolved reports whether provider discovery has already completed successfully.
func (a *Auth) Resolved() bool {
	a.provider.mu.Lock()
	defer a.provider.mu.Unlock()

	return a.provider.current != nil
}

// ProviderResolve resolves the provider now and reports whether discovery succeeded.
func (a *Auth) ProviderResolve() (bool, error) {
	_, err := a.provider.resolve()

	return err == nil, err
}

func (a *Auth) callbackURL(c *echo.Context) string {
	if appURL := a.Settings().AppURL; appURL != "" {
		return strings.TrimSuffix(appURL, "/") + a.CallbackPath
	}

	return c.Scheme() + "://" + c.Request().Host + a.CallbackPath
}

// maxRedirectDecodePasses bounds how often SanitizeRedirect percent-decodes a target before
// judging it, covering browsers that decode once per redirect hop.
const maxRedirectDecodePasses = 3

// SanitizeRedirect keeps only same-origin absolute paths and falls back to "/" for anything else.
// Percent-encoded and backslash variants that browsers normalize back into protocol-relative
// URLs, such as "/%2F%2Fevil.example.com", are rejected as well.
func SanitizeRedirect(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return "/"
	}

	decoded := raw
	for range maxRedirectDecodePasses {
		unescaped, err := url.PathUnescape(decoded)
		if err != nil || unescaped == decoded {
			break
		}

		decoded = unescaped
	}

	if !strings.HasPrefix(decoded, "/") || strings.HasPrefix(decoded, "//") ||
		strings.Contains(decoded, "\\") || strings.ContainsRune(decoded, 0) {
		return "/"
	}

	return raw
}
