package gosso

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	stateCookieTTL = 10 * time.Minute
	stateSeparator = "|"
)

// Auth runs the login lifecycle and the session middleware for a single app.
// Handlers take the plain (http.ResponseWriter, *http.Request) pair so gosso
// stays framework-agnostic.
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
func (a *Auth) StartLogin(w http.ResponseWriter, r *http.Request, redirect string) error {
	config := a.Settings()
	if err := config.Validate(); err != nil {
		return err
	}

	login, err := a.provider.Login(config, a.callbackURL(r))
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

	a.clearLoginState(w)
	http.SetCookie(w, a.stateCookie(value, int(stateCookieTTL.Seconds()), time.Time{}))

	http.Redirect(w, r, login.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)

	return nil
}

// ConsumeLoginState validates and clears the state cookie and returns the state, PKCE verifier and redirect target.
// The cookie is cleared before it is read on purpose: one-shot semantics come from the response
// expiring it, while the request copy stays readable for this handler.
func (a *Auth) ConsumeLoginState(w http.ResponseWriter, r *http.Request) (state, verifier, redirect string, err error) {
	a.clearLoginState(w)

	cookie, cookieErr := r.Cookie(a.stateCookieName())
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
func (a *Auth) Exchange(r *http.Request, code, verifier string) (string, error) {
	config := a.Settings()

	return a.provider.Exchange(r.Context(), config, code, verifier, a.callbackURL(r))
}

// StartSession stores a session for subject through the configured SessionManager.
func (a *Auth) StartSession(w http.ResponseWriter, r *http.Request, subject string) error {
	return a.Sessions.Start(w, r, subject, time.Now().Add(a.SessionTTL()))
}

// Authenticate resolves the current user from the session store.
func (a *Auth) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	return a.Sessions.Authenticate(w, r)
}

// ClearSession removes the local session, without contacting the provider.
func (a *Auth) ClearSession(w http.ResponseWriter, r *http.Request) {
	a.Sessions.Clear(w, r)
}

// SessionTTL returns the configured session lifetime, falling back to DefaultSessionTTL.
func (a *Auth) SessionTTL() time.Duration {
	return a.Settings().EffectiveSessionTTL()
}

// HandleCallback finishes the OIDC login for a callback request: it rejects provider-reported
// errors, consumes and checks the state cookie, exchanges the code, applies AuthorizeSubject
// and starts the session. It returns the login result or a classified failure for the login
// page redirect.
func (a *Auth) HandleCallback(w http.ResponseWriter, r *http.Request) (*LoginResult, *LoginFailure) {
	if raw := r.URL.Query().Get("error"); raw != "" {
		return nil, &LoginFailure{Code: LoginErrorRejected, Cause: fmt.Errorf("provider reported %q", raw)}
	}

	state, verifier, redirect, err := a.ConsumeLoginState(w, r)
	if err != nil {
		return nil, &LoginFailure{Code: LoginErrorExpired, Cause: err}
	}

	if r.URL.Query().Get("state") != state {
		return nil, &LoginFailure{Code: LoginErrorExpired, Cause: ErrStateMismatch}
	}

	subject, err := a.Exchange(r, r.URL.Query().Get("code"), verifier)
	if err != nil {
		return nil, &LoginFailure{Code: ClassifyLoginError(err), Cause: err}
	}

	if a.AuthorizeSubject != nil && !a.AuthorizeSubject(subject) {
		return nil, &LoginFailure{Code: LoginErrorRejected, Cause: ErrSubjectUnauthorized}
	}

	if err := a.StartSession(w, r, subject); err != nil {
		return nil, &LoginFailure{Code: LoginErrorFailed, Cause: err}
	}

	if redirect == "" {
		redirect = "/"
	}

	return &LoginResult{Subject: subject, Redirect: redirect}, nil
}

// Middleware redirects unauthenticated requests to LoginPath, or answers 401 when no login path is set.
// It returns stdlib middleware; frameworks can wrap it, e.g. echo.WrapMiddleware or chi.Middleware.
func (a *Auth) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.Enabled() {
				next.ServeHTTP(w, r)

				return
			}

			if _, err := a.Authenticate(w, r); err != nil {
				if a.LoginPath == "" {
					http.Error(w, "Authentication required", http.StatusUnauthorized)

					return
				}

				http.Redirect(w, r, a.LoginPath, http.StatusFound)

				return
			}

			next.ServeHTTP(w, r)
		})
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
	return a.Settings().CookieOptions().Cookie(a.stateCookieName(), value, maxAge, expires)
}

func (a *Auth) clearLoginState(w http.ResponseWriter) {
	http.SetCookie(w, a.stateCookie("", -1, time.Time{}))
}

func (a *Auth) callbackURL(r *http.Request) string {
	if appURL := a.Settings().AppURL; appURL != "" {
		return strings.TrimSuffix(appURL, "/") + a.CallbackPath
	}

	return Scheme(r) + "://" + r.Host + a.CallbackPath
}

// Provider returns the OIDC provider behind this Auth, for apps that need to
// inspect discovery state or force a resolve in their own tests or health checks.
func (a *Auth) Provider() *Provider {
	return a.provider
}

// CallbackURL returns the redirect URI registered with the provider for this request.
func (a *Auth) CallbackURL(r *http.Request) string {
	return a.callbackURL(r)
}
