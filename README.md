# gosso

Shared OpenID Connect login package used by [GoDash](https://github.com/flohoss/godash), [GoCron](https://github.com/flohoss/gocron) and friends. One implementation of the browser handshake, cookie handling and session strategies so the apps behave identically: separate login page, `/auth/callback`, PKCE S256, state cookie, optional `app_url` for redirect- and proxy-safe callback URLs.

## Install

```sh
go get github.com/flohoss/gosso@v0.1.0
```

Requires Go 1.27 or newer.

## What it provides

- `Config` — issuer, client credentials, session TTL, `cookie_secure`, `app_url`, cookie prefix. `Validate()` enforces issuer/secret rules.
- `Auth` — Echo v5 middleware and login lifecycle:
  - `StartLogin(ctx, redirect)` — sets the `*_oidc_state` cookie (state + PKCE verifier + optional redirect target, HttpOnly, SameSite=Lax, 10 minute TTL) and 302s to the provider.
  - `ConsumeLoginState(ctx)` — validates and clears the state cookie, returns state, verifier and the sanitized redirect target.
  - `Exchange(ctx, code, verifier)` — code exchange and `id_token` verification, returns the subject.
  - `Authenticate`, `ClearSession`, `SessionTTL`, `Middleware`.
- `SessionManager` interface — bring your own store (DB-backed jti, like GoCron's SQLite sessions) or use the built-in:
- `HMACSessions` — stateless signed cookie (`subject|expiry` + HMAC-SHA256, base64url), sliding refresh once half the TTL has passed. Requires a `SessionKey` of at least 32 characters (`gosso.MinSessionKeyLength`).
- `LoginError` codes (`rejected`, `expired`, `unavailable`, `failed`) and `ClassifyLoginError(err)` so handlers can redirect to the login page with the same error codes everywhere.
- Lazy background discovery (`provider.Warm`) with a 10 second timeout; failed discovery is retried on the next request instead of being cached.

## Cookie naming

Cookies are `<cookie_prefix>_oidc_state` and `<cookie_prefix>_session`. `Config.CookiePrefix` defaults to the client ID, so give each app a distinct client ID (or set the prefix) to avoid collisions on a shared domain.

## Usage sketch

```go
sessions := gosso.NewHMACSessions(gosso.HMACOptions{
	Prefix:   "myapp",
	Settings: func() gosso.Config { return config.SSO() },
})

auth := gosso.New(
	func() gosso.Config { return config.SSO() },
	sessions,
	"/auth/callback",
	"/login",
)

e.GET("/login", loginPage)
e.GET("/auth/oidc", func(c *echo.Context) error { return auth.StartLogin(c, c.QueryParam("redirect")) })
e.GET("/auth/callback", func(c *echo.Context) error {
	state, verifier, redirect, err := auth.ConsumeLoginState(c)
	if err != nil {
		return c.Redirect(http.StatusFound, "/login?error=expired")
	}
	if c.QueryParam("state") != state {
		return c.Redirect(http.StatusFound, "/login?error=expired")
	}
	subject, err := auth.Exchange(c, c.QueryParam("code"), verifier)
	if err != nil {
		return c.Redirect(http.StatusFound, "/login?error="+string(gosso.ClassifyLoginError(err)))
	}
	if err := auth.StartSession(c, subject); err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, redirect)
})

e.Use(auth.Middleware())
```

Settings should come from the app config so hot reloads take effect; read them through the `func() Config` indirection.

## Logout

`ClearSession` only clears the local session — no round-trip to a provider `end_session_endpoint`. For DB-backed stores also delete the stored session row before clearing the cookie.

## License

MIT
