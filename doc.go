// Package gosso implements the shared OpenID Connect login used by GoCron and GoRss:
// the browser handshake, the state cookie, PKCE S256 code exchange against a
// discovered provider, the login/logout/me routes and a SQLite-backed session store.
//
// The package is Echo-native. Mount registers the lifecycle routes, publishes the
// session cookie as an OpenAPI security scheme and returns the Huma API of the
// session-protected group, so an app registers its own operations on it and they
// require a login:
//
//	auth, err := gosso.New(gosso.Options{
//		Enabled:      cfg.Enabled,
//		IssuerURL:    cfg.IssuerURL,
//		ClientID:     cfg.ClientID,
//		ClientSecret: cfg.ClientSecret,
//		SessionTTL:   cfg.SessionTTL,
//		CookieSecure: cfg.CookieSecure,
//		AppURL:       cfg.AppURL,
//		DB:           db,
//	})
//	if err != nil {
//		return err
//	}
//
//	api := auth.Mount(router, humaConfig)
//
// Sessions live in the sso_sessions table, which New creates. Expired rows are
// removed by Cleanup, which the app runs for as long as it serves requests.
// Options are read once, so a credential change needs a restart; the app's own
// config hot reload keeps working for everything else.
package gosso
