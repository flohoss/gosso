package gosso

import (
	"errors"
	"log/slog"
	"os"
)

var (
	ErrUnauthenticated     = errors.New("not authenticated")
	ErrProviderUnavailable = errors.New("identity provider is not reachable")
	ErrInvalidSessionKey   = errors.New("session signing key must be at least 32 characters")
)

type LoginError string

const (
	LoginErrorRejected    LoginError = "rejected"
	LoginErrorExpired     LoginError = "expired"
	LoginErrorUnavailable LoginError = "unavailable"
	LoginErrorFailed      LoginError = "failed"

	LoginQueryParam = "error"
)

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

func ValidLoginErrorCode(raw string) bool {
	switch LoginError(raw) {
	case LoginErrorRejected, LoginErrorExpired, LoginErrorUnavailable, LoginErrorFailed:
		return true
	default:
		return false
	}
}

var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

func SetLogger(l *slog.Logger) {
	if l != nil {
		logger = l
	}
}
