package gosso

import (
	"context"

	"github.com/labstack/echo/v5"
)

type echoContextKey struct{}

// EchoContextMiddleware stores the Echo context on the request so Huma handlers,
// which only receive a context.Context, can reach the response and its cookies.
func EchoContextMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		c.SetRequest(c.Request().WithContext(context.WithValue(c.Request().Context(), echoContextKey{}, c)))

		return next(c)
	}
}

// EchoContextFrom returns the Echo context stored by EchoContextMiddleware.
func EchoContextFrom(ctx context.Context) *echo.Context {
	c, _ := ctx.Value(echoContextKey{}).(*echo.Context)

	return c
}
