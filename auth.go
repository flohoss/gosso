package gosso

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/oauth2"
)

const (
	stateCookieTTL = 10 * time.Minute
	stateSeparator = "|"
)

type Auth struct {
	Sessions SessionManager

	Settings     func() Config
	CallbackPath string
	LoginPath    string

	provider *Provider
}

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

func (a *Auth) Enabled() bool {
	if a == nil {
		return false
	}

	return a.Settings().Enabled
}

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

func (a *Auth) Exchange(echoContext *echo.Context, code, verifier string) (string, error) {
	config := a.Settings()

	return a.provider.Exchange(echoContext.Request().Context(), config, code, verifier, a.callbackURL(echoContext))
}

func (a *Auth) StartSession(echoContext *echo.Context, subject string) error {
	return a.Sessions.Start(echoContext, subject, time.Now().Add(a.SessionTTL()))
}

func (a *Auth) Authenticate(echoContext *echo.Context) (*User, error) {
	return a.Sessions.Authenticate(echoContext)
}

func (a *Auth) ClearSession(echoContext *echo.Context) {
	a.Sessions.Clear(echoContext)
}

func (a *Auth) SessionTTL() time.Duration {
	ttl := a.Settings().SessionTTL
	if ttl <= 0 {
		return DefaultSessionTTL
	}

	return ttl
}

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
	config := a.Settings()
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

func (a *Auth) CallbackURL(c *echo.Context) string {
	return a.callbackURL(c)
}

func (a *Auth) Resolved() bool {
	a.provider.mu.Lock()
	defer a.provider.mu.Unlock()

	return a.provider.current != nil
}

func (a *Auth) callbackURL(c *echo.Context) string {
	if appURL := a.Settings().AppURL; appURL != "" {
		return strings.TrimSuffix(appURL, "/") + a.CallbackPath
	}

	return c.Scheme() + "://" + c.Request().Host + a.CallbackPath
}

func SanitizeRedirect(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}

	return raw
}
