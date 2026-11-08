package gosso

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humaecho"
	"github.com/labstack/echo/v5"
)

// SecurityScheme is the OpenAPI security scheme name of the session cookie.
const SecurityScheme = "cookieAuth"

const cleanupInterval = time.Hour

// Mount registers the login and callback routes, publishes the session cookie as
// an OpenAPI security scheme and returns the Huma API bound to the session-protected
// group, so app operations registered on it require a login. When SSO is disabled the
// lifecycle routes answer 404 and the group lets every request through.
func (a *Auth) Mount(e *echo.Echo, config huma.Config) huma.API {
	e.GET(LoginRoute, a.loginHandler)
	e.GET(CallbackRoute, a.callbackHandler)

	if config.OpenAPI == nil {
		config.OpenAPI = &huma.OpenAPI{}
	}
	if config.OpenAPI.Components == nil {
		config.OpenAPI.Components = &huma.Components{}
	}
	if config.OpenAPI.Components.SecuritySchemes == nil {
		config.OpenAPI.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	config.OpenAPI.Components.SecuritySchemes[SecurityScheme] = &huma.SecurityScheme{
		Type:        "apiKey",
		Name:        a.opts.CookieName,
		In:          "cookie",
		Description: "Session cookie issued by " + CallbackRoute + ".",
	}

	protected := humaecho.NewWithGroup(e, e.Group("", a.Middleware()), config)

	// Built after the protected API so the spec, docs and schema routes end up on
	// the public router instead of behind the session middleware. The me and logout
	// routes stay public: the SPA has to learn that auth is enabled before it can
	// redirect to the login page, and both are safe without a session.
	public := humaecho.New(e, config)
	huma.Register(public, logoutOperation(), a.logoutHandler)
	huma.Register(public, meOperation(), a.meHandler)

	return protected
}

func (a *Auth) loginHandler(c *echo.Context) error {
	if !a.Enabled() {
		return echo.NewHTTPError(http.StatusNotFound, "Not found")
	}

	if err := a.StartLogin(c, c.QueryParam("redirect")); err != nil {
		slog.Error("Failed to start login", "error", err)

		return c.Redirect(http.StatusFound, LoginPageURL(ClassifyLoginError(err)))
	}

	return nil
}

func (a *Auth) callbackHandler(c *echo.Context) error {
	if !a.Enabled() {
		return echo.NewHTTPError(http.StatusNotFound, "Not found")
	}

	result, failure := a.HandleCallback(c)
	if failure != nil {
		LogFailure(failure)

		return c.Redirect(http.StatusFound, LoginPageURL(failure.Code))
	}

	slog.Info("User logged in", "subject", result.Subject)

	return c.Redirect(http.StatusFound, result.Redirect)
}

func logoutOperation() huma.Operation {
	return huma.Operation{
		OperationID: "post-auth-logout",
		Method:      http.MethodPost,
		Path:        LogoutRoute,
		Summary:     "Logout",
		Description: "Revokes the current session and clears the session cookie.",
		Tags:        []string{"Auth"},
		Security:    []map[string][]string{{SecurityScheme: {}}},
	}
}

func meOperation() huma.Operation {
	return huma.Operation{
		OperationID: "get-auth-me",
		Method:      http.MethodGet,
		Path:        MeRoute,
		Summary:     "Get current user",
		Description: "Returns whether single sign-on is enabled and the identity of the current session.",
		Tags:        []string{"Auth"},
		Security:    []map[string][]string{{SecurityScheme: {}}},
	}
}

// CurrentUserBody is the payload of the me route.
type CurrentUserBody struct {
	Authenticated bool `json:"authenticated"`
	AuthEnabled   bool `json:"auth_enabled" doc:"Whether single sign-on is enabled on this instance."`
}

// LogoutBody is the payload of the logout route.
type LogoutBody struct {
	Redirect string `json:"redirect" doc:"Where the SPA should navigate after the session was cleared. Always '/'; provider-side logout is out of scope."`
}

type logoutResponse struct {
	Body LogoutBody
}

type currentUserResponse struct {
	Body CurrentUserBody
}

func (a *Auth) logoutHandler(ctx context.Context, _ *struct{}) (*logoutResponse, error) {
	a.ClearSession(EchoContextFrom(ctx))

	return &logoutResponse{Body: LogoutBody{Redirect: "/"}}, nil
}

func (a *Auth) meHandler(ctx context.Context, _ *struct{}) (*currentUserResponse, error) {
	if !a.Enabled() {
		return &currentUserResponse{Body: CurrentUserBody{AuthEnabled: false}}, nil
	}

	if _, err := a.Authenticate(EchoContextFrom(ctx)); err != nil {
		return &currentUserResponse{Body: CurrentUserBody{AuthEnabled: true}}, nil
	}

	return &currentUserResponse{Body: CurrentUserBody{Authenticated: true, AuthEnabled: true}}, nil
}

// Cleanup deletes expired sessions now and then every hour until ctx is done.
func (a *Auth) Cleanup(ctx context.Context) {
	a.sessions.deleteExpired()

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.sessions.deleteExpired()
		case <-ctx.Done():
			return
		}
	}
}
