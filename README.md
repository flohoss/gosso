<a href="https://pkg.go.dev/github.com/flohoss/gosso/v2"><img src="https://pkg.go.dev/badge/github.com/flohoss/gosso/v2.svg" alt="Go Reference"></a>
[![CI](https://github.com/flohoss/gosso/actions/workflows/ci.yml/badge.svg)](https://github.com/flohoss/gosso/actions/workflows/ci.yml)

Shared OpenID Connect login package used by [GoDash](https://github.com/flohoss/godash), [GoCron](https://github.com/flohoss/gocron) and friends. One implementation of the browser handshake, cookie handling and session strategies so the apps behave identically: separate login page, `/auth/callback`, PKCE S256, state cookie, optional `app_url` for redirect- and proxy-safe callback URLs.

The core is framework-agnostic: every handler takes the plain `(http.ResponseWriter, *http.Request)` pair and `Middleware` returns `func(http.Handler) http.Handler`, so it works with net/http, Echo, chi, gin and friends.

## Install

```sh
go get github.com/flohoss/gosso/v2@v2.0.0
```

Requires Go 1.27.3 or newer.

## What it provides

- `Config` — issuer, client credentials, session TTL, `cookie_secure`, `app_url`, cookie prefix. `Validate()` enforces issuer/secret/session-key rules.
- `Auth` — the login lifecycle and session middleware:
  - `StartLogin(w, r, redirect)` — sets the `*_oidc_state` cookie (state + PKCE verifier + optional redirect target, HttpOnly, SameSite=Lax, 10 minute TTL) and 302s to the provider.
  - `HandleCallback(w, r)` — runs the whole callback choreography: provider-reported errors, state cookie consumption and match, code exchange with PKCE, the optional `AuthorizeSubject` gate and the session start. Returns either `*LoginResult{Subject, Redirect}` or `*LoginFailure{Code, Cause}` for the login page redirect.
  - `Exchange(r, code, verifier)` — code exchange and `id_token` verification on its own, returns the subject.
  - `Authenticate(w, r)`, `ClearSession(w, r)`, `StartSession(w, r, subject)`, `SessionTTL`, `CallbackURL(r)`.
  - `Middleware()` — stdlib middleware; unauthenticated requests are redirected to `LoginPath`, or answered with 401 when no login path is set.
- `SessionManager` interface — bring your own store (DB-backed jti, like GoCron's SQLite sessions) or use the built-in:
- `HMACSessions` — stateless signed cookie (`subject|expiry` + HMAC-SHA256, base64url), sliding refresh once half the TTL has passed. Requires a `SessionKey` of at least 32 characters (`gosso/v2.MinSessionKeyLength`). Stateless cookies cannot be revoked before their expiry — implement `SessionManager` when immediate revocation matters.
- `LoginError` codes (`rejected`, `expired`, `unavailable`, `failed`), `ClassifyLoginError(err)` and `LogFailure(failure)` so every handler redirects and logs with the same codes and severities.
- Lazy background discovery (`provider.Warm`) with a 10 second timeout; failed discovery is retried on the next request instead of being cached. `auth.Provider().Resolved()` and `.Resolve()` expose the state for health checks.

## Cookie naming

Cookies are `<cookie_prefix>_oidc_state` (from `Config.CookiePrefix`, which defaults to the client ID) and the session cookie named by your `SessionManager`. `HMACSessions` takes the name from `HMACOptions.CookieName`, or `HMACOptions.Prefix` + `_session`. Give each app a distinct client ID (or set the prefix/name) to avoid collisions on a shared domain.

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

mux := http.NewServeMux()
mux.HandleFunc("GET /login", loginPage)
mux.HandleFunc("GET /auth/oidc", func(w http.ResponseWriter, r *http.Request) {
	if err := auth.StartLogin(w, r, r.URL.Query().Get("redirect")); err != nil {
		http.Redirect(w, r, "/login?error="+string(gosso.ClassifyLoginError(err)), http.StatusFound)
	}
})
mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
	result, failure := auth.HandleCallback(w, r)
	if failure != nil {
		gosso.LogFailure(failure)
		http.Redirect(w, r, "/login?error="+string(failure.Code), http.StatusFound)

		return
	}

	slog.Info("User logged in", "subject", result.Subject)
	http.Redirect(w, r, result.Redirect, http.StatusFound)
})

// Protect everything else: 302 to /login, or 401 when LoginPath is empty.
http.ListenAndServe(":8443", auth.Middleware()(mux))
```

Settings should come from the app config so hot reloads take effect; read them through the `func() Config` indirection.

Frameworks wrap the middleware instead of mounting the handler: `echo.WrapMiddleware(auth.Middleware())`, `chi.Middleware(auth.Middleware())` or the framework's equivalent.

## Logout

`ClearSession` only clears the local session — no round-trip to a provider `end_session_endpoint`. For DB-backed stores also delete the stored session row before clearing the cookie.

## License

MIT
