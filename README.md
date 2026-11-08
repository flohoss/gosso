<a href="https://pkg.go.dev/github.com/flohoss/gosso/v3"><img src="https://pkg.go.dev/badge/github.com/flohoss/gosso/v3.svg" alt="Go Reference"></a>
[![CI](https://github.com/flohoss/gosso/actions/workflows/ci.yml/badge.svg)](https://github.com/flohoss/gosso/actions/workflows/ci.yml)

Shared OpenID Connect login used by [GoCron](https://github.com/flohoss/gocron) and [GoRss](https://github.com/flohoss/gorss). One implementation of the browser handshake, cookie handling, SQLite session store and auth routes so the apps behave identically: separate login page, `/api/auth/callback`, PKCE S256, state cookie, optional `app_url` for redirect- and proxy-safe callback URLs.

The package is Echo- and Huma-native: `Auth.Mount` registers the lifecycle routes, publishes the session cookie as an OpenAPI security scheme and returns the Huma API bound to the session-protected group. `main.go` initializes it once with `gosso.Options`.

## Install

```sh
go get github.com/flohoss/gosso/v3
```

Requires Go 1.27.3 or newer.

## What it provides

- `Options` — issuer, client credentials, session TTL, `cookie_secure`, `app_url`, cookie prefix/name, login path, scopes and the `*sql.DB` for the session store. `Validate()` enforces the issuer rules.
- `New(Options)` — validates, creates the `sso_sessions` table and warms provider discovery in the background. A disabled instance still builds, so SSO can be shipped off and enabled by config.
- `Auth.Mount(e, humaConfig)` — registers `GET /api/auth/login`, `GET /api/auth/callback`, adds `cookieAuth` to the OpenAPI security schemes and returns a `huma.API` whose routes run behind the session middleware. Also mounts the public `POST /api/auth/logout` and `GET /api/auth/me`.
- `Auth.Middleware()` — Echo group middleware; unauthenticated requests are redirected to `Options.LoginPath`, or answered with 401 when it is empty.
- `Auth.Authenticate(c)`, `Auth.ClearSession(c)`, `Auth.StartLogin(c, redirect)`, `Auth.HandleCallback(c)`, `Auth.SessionCookieName()`.
- `Auth.Cleanup(ctx)` — deletes expired sessions immediately, then hourly until the context is done.
- `LoginError` codes (`rejected`, `expired`, `unavailable`, `failed`), `ClassifyLoginError(err)`, `LoginPageURL(code)` and `LogFailure(failure)` so handlers redirect and log with the same codes and severities.
- Lazy background discovery with a 10 second timeout; failed discovery is retried on the next request instead of being cached. `Auth.Provider().Resolved()` and `.Resolve()` expose the state for health checks.

## Usage

```go
auth, err := gosso.New(gosso.Options{
	Enabled:      config.GetAuth().OIDC.Enabled,
	IssuerURL:    config.GetAuth().OIDC.IssuerURL,
	ClientID:     config.GetAuth().OIDC.ClientID,
	ClientSecret: config.GetAuth().OIDC.ClientSecret,
	SessionTTL:   config.GetAuth().OIDC.SessionTTL,
	CookieSecure: config.GetAuth().OIDC.CookieSecure,
	LoginPath:    "/login",
	AppURL:       config.GetAppUrl(),
	DB:           db,
})
if err != nil {
	slog.Error(err.Error())
	os.Exit(1)
}

go auth.Cleanup(ctx)

e := echo.New()
e.Use(gosso.EchoContextMiddleware)

api := auth.Mount(e, huma.DefaultConfig("My API", buildinfo.Version))
huma.Register(api, listItemsOperation(), listItemsHandler) // requires a login

// The SPA shell is not behind the middleware; check it explicitly.
e.GET("/login", loginPage)
e.GET("/*", func(c *echo.Context) error {
	if auth.Enabled() {
		if _, err := auth.Authenticate(c); err != nil {
			return c.Redirect(http.StatusFound, gosso.LoginPagePath)
		}
	}

	return c.Render(http.StatusOK, "index.html", nil)
})
```

`EchoContextMiddleware` stores the Echo context on the request so Huma handlers, which
only receive a `context.Context`, can reach the response cookies through
`gosso.EchoContextFrom(ctx)`.

## Cookie naming

The state cookie is `<cookie_prefix>_oidc_state`, where `cookie_prefix` defaults to the
sanitized client ID; the session cookie is `<cookie_prefix>_session` unless `Options.CookieName`
is set. Give each app a distinct client ID (or set the prefix) to avoid collisions on a shared domain.

## Logout

Logout revokes the stored session row and expires the cookie; there is no round-trip to a
provider `end_session_endpoint`.

## License

MIT
