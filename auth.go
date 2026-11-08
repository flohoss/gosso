package gosso

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/oauth2"
)

const (
	// CallbackRoute is the registered redirect URI of the OIDC handshake.
	CallbackRoute = "/api/auth/callback"
	// LoginRoute starts the handshake and is linked from the login page.
	LoginRoute = "/api/auth/login"
	// LogoutRoute revokes the session.
	LogoutRoute = "/api/auth/logout"
	// MeRoute reports the current identity.
	MeRoute = "/api/auth/me"
	// LoginPagePath is the page unauthenticated browsers are redirected to.
	LoginPagePath = "/login"

	stateCookieTTL = 10 * time.Minute
	stateSeparator = "|"
)

// Auth runs the login lifecycle, the session store and the middleware for one app.
type Auth struct {
	opts     Options
	provider *Provider
	sessions *sessionStore
}

// New validates the options, prepares the session store and warms provider discovery.
func New(opts Options) (*Auth, error) {
	if opts.DB == nil {
		return nil, ErrMissingDatabase
	}

	opts = opts.withDefaults()

	if opts.Enabled {
		if err := opts.Validate(); err != nil {
			return nil, err
		}
	}

	sessions, err := newSessionStore(opts)
	if err != nil {
		return nil, err
	}

	auth := &Auth{
		opts:     opts,
		provider: newProvider(opts),
		sessions: sessions,
	}

	if auth.Enabled() {
		auth.provider.Warm()
	}

	return auth, nil
}

// Enabled reports whether SSO is switched on, tolerating a nil receiver.
func (a *Auth) Enabled() bool {
	if a == nil {
		return false
	}

	return a.opts.Enabled
}

// SessionCookieName is the name of the cookie carrying the session identifier.
func (a *Auth) SessionCookieName() string {
	return a.opts.CookieName
}

// Provider exposes discovery state for health checks and tests.
func (a *Auth) Provider() *Provider {
	return a.provider
}

// Middleware protects a route group. Unauthenticated requests are redirected to
// Options.LoginPath, or answered with 401 when no login path is set.
func (a *Auth) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if !a.Enabled() {
				return next(c)
			}

			if _, err := a.Authenticate(c); err != nil {
				if a.opts.LoginPath == "" {
					return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
				}

				return c.Redirect(http.StatusFound, a.opts.LoginPath)
			}

			return next(c)
		}
	}
}

// Authenticate resolves the current user from the session store.
func (a *Auth) Authenticate(c *echo.Context) (*User, error) {
	return a.sessions.authenticate(c.Request())
}

// ClearSession revokes the stored session and expires the cookie.
func (a *Auth) ClearSession(c *echo.Context) {
	a.sessions.clear(c.Response(), c.Request())
}

// StartLogin writes the state cookie and redirects the browser to the provider.
func (a *Auth) StartLogin(c *echo.Context, redirect string) error {
	w, r := c.Response(), c.Request()

	if err := a.opts.Validate(); err != nil {
		return err
	}

	login, _, err := a.provider.oauthConfig(a.callbackURL(r))
	if err != nil {
		return err
	}

	state := RandomToken()
	verifier := oauth2.GenerateVerifier()

	value := state + stateSeparator + verifier
	if target := SanitizeRedirect(redirect); target != "/" {
		value += stateSeparator + target
	}

	a.clearLoginState(w)
	http.SetCookie(w, newCookie(a.opts.stateCookieName(), value, int(stateCookieTTL.Seconds()), time.Time{}, a.opts.CookieSecure))

	return c.Redirect(http.StatusFound, login.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)))
}

// HandleCallback finishes the OIDC login and returns the result or a classified failure.
func (a *Auth) HandleCallback(c *echo.Context) (*LoginResult, *LoginFailure) {
	w, r := c.Response(), c.Request()

	if raw := r.URL.Query().Get("error"); raw != "" {
		return nil, &LoginFailure{Code: LoginErrorRejected, Cause: errors.New("provider reported " + raw)}
	}

	state, verifier, redirect, err := a.consumeLoginState(w, r)
	if err != nil {
		return nil, &LoginFailure{Code: LoginErrorExpired, Cause: err}
	}

	if r.URL.Query().Get("state") != state {
		return nil, &LoginFailure{Code: LoginErrorExpired, Cause: ErrStateMismatch}
	}

	subject, err := a.provider.exchange(r.Context(), r.URL.Query().Get("code"), verifier, a.callbackURL(r))
	if err != nil {
		return nil, &LoginFailure{Code: ClassifyLoginError(err), Cause: err}
	}

	if err := a.sessions.start(w, r, subject); err != nil {
		return nil, &LoginFailure{Code: LoginErrorFailed, Cause: err}
	}

	return &LoginResult{Subject: subject, Redirect: redirect}, nil
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

func (a *Auth) consumeLoginState(w http.ResponseWriter, r *http.Request) (state, verifier, redirect string, err error) {
	a.clearLoginState(w)

	cookie, cookieErr := r.Cookie(a.opts.stateCookieName())
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

func (a *Auth) clearLoginState(w http.ResponseWriter) {
	http.SetCookie(w, newCookie(a.opts.stateCookieName(), "", -1, time.Time{}, a.opts.CookieSecure))
}
