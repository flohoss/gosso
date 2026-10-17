package gosso

import (
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
)

var (
	// ErrUnauthenticated is returned when no valid session is present.
	ErrUnauthenticated = errors.New("not authenticated")
	// ErrProviderUnavailable is returned when OIDC discovery could not reach the issuer.
	ErrProviderUnavailable = errors.New("identity provider is not reachable")
	// ErrInvalidSessionKey is returned by ValidateSessionKey for short signing keys.
	ErrInvalidSessionKey = errors.New("session signing key must be at least 32 characters")
	// ErrStateMismatch is returned when the callback state does not match the login state cookie.
	ErrStateMismatch = errors.New("callback state does not match the login state")
	// ErrSubjectUnauthorized is returned when AuthorizeSubject refuses a verified subject.
	ErrSubjectUnauthorized = errors.New("subject is not authorized to sign in")
)

// LoginError is the stable code an app redirects to its login page with.
type LoginError string

const (
	// LoginErrorRejected marks a login the provider refused.
	LoginErrorRejected LoginError = "rejected"
	// LoginErrorExpired marks a missing, stale or mismatched login state.
	LoginErrorExpired LoginError = "expired"
	// LoginErrorUnavailable marks an unreachable identity provider.
	LoginErrorUnavailable LoginError = "unavailable"
	// LoginErrorFailed marks any other login failure.
	LoginErrorFailed LoginError = "failed"

	// LoginQueryParam is the query parameter carrying a LoginError code on the login page.
	LoginQueryParam = "error"
)

// ClassifyLoginError maps an error to the LoginError code a handler should redirect with.
func ClassifyLoginError(err error) LoginError {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrProviderUnavailable):
		return LoginErrorUnavailable
	default:
		return LoginErrorFailed
	}
}

// ValidLoginErrorCode reports whether raw is one of the known LoginError codes.
func ValidLoginErrorCode(raw string) bool {
	switch LoginError(raw) {
	case LoginErrorRejected, LoginErrorExpired, LoginErrorUnavailable, LoginErrorFailed:
		return true
	default:
		return false
	}
}

var logger atomic.Pointer[slog.Logger]

func init() {
	logger.Store(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
}

// SetLogger replaces the package logger used for discovery diagnostics. A nil logger is ignored.
func SetLogger(l *slog.Logger) {
	if l != nil {
		logger.Store(l)
	}
}
