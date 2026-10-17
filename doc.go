// Package gosso implements the shared OpenID Connect login flow used by GoDash,
// GoCron and friends: the browser handshake, state and session cookies, PKCE S256
// code exchange against a discovered provider, and pluggable session storage.
//
// Start with Config for the issuer credentials and Auth for the Echo v5 routes and
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
