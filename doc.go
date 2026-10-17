// Package gosso implements the shared OpenID Connect login flow used by GoDash,
// GoCron and friends: the browser handshake, state and session cookies, PKCE S256
// code exchange against a discovered provider, and pluggable session storage.
//
// The core is framework-agnostic: handlers and the SessionManager interface work
// with the plain (http.ResponseWriter, *http.Request) pair, and Middleware returns
// stdlib middleware that any router can wrap.
//
// Start with Config for the issuer credentials and Auth for the routes and
// middleware. HandleCallback runs the whole callback choreography and returns either
// a LoginResult or a classified LoginFailure for the login page redirect;
// Auth.AuthorizeSubject can optionally refuse sessions for individual subjects.
// HMACSessions is the built-in signed-cookie SessionManager — its sessions are
// stateless and cannot be revoked before their expiry. Implement SessionManager to
// back sessions with your own store when immediate revocation matters.
//
// Settings are read through a func() Config indirection so apps can reload
// configuration without rebuilding the Auth instance.
package gosso
