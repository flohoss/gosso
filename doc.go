// Package gosso implements the shared OpenID Connect login flow used by GoDash,
// GoCron and friends: the browser handshake, state and session cookies, PKCE S256
// code exchange against a discovered provider, and pluggable session storage.
//
// Start with Config for the issuer credentials and Auth for the Echo v5 routes and
// middleware. HMACSessions is the built-in signed-cookie SessionManager; implement
// SessionManager to back sessions with your own store instead.
//
// Settings are read through a func() Config indirection so apps can reload
// configuration without rebuilding the Auth instance.
package gosso
