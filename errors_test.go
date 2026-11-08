package gosso

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestClassifyLoginError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want LoginError
	}{
		{name: "success", err: nil, want: ""},
		{name: "provider unavailable", err: ErrProviderUnavailable, want: LoginErrorUnavailable},
		{name: "wrapped provider unavailable", err: fmt.Errorf("discovery: %w", ErrProviderUnavailable), want: LoginErrorUnavailable},
		{name: "anything else", err: errors.New("boom"), want: LoginErrorFailed},
	}

	for _, tc := range cases {
		if got := ClassifyLoginError(tc.err); got != tc.want {
			t.Errorf("%s: ClassifyLoginError(%v) = %q, want %q", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestValidLoginErrorCode(t *testing.T) {
	for _, valid := range []string{"rejected", "expired", "unavailable", "failed"} {
		if !ValidLoginErrorCode(valid) {
			t.Errorf("expected %q to be a valid login error code", valid)
		}
	}

	for _, invalid := range []string{"", "bogus", "EXPIRED"} {
		if ValidLoginErrorCode(invalid) {
			t.Errorf("expected %q to be rejected", invalid)
		}
	}
}

func TestSetLogger_IgnoresNil(t *testing.T) {
	before := logger.Load()

	SetLogger(nil)
	if logger.Load() != before {
		t.Fatal("expected a nil logger to be ignored")
	}
}

func TestSetLogger_ReplacesTheLogger(t *testing.T) {
	before := logger.Load()
	t.Cleanup(func() { SetLogger(before) })

	replacement := slog.New(slog.NewTextHandler(io.Discard, nil))
	SetLogger(replacement)

	if logger.Load() != replacement {
		t.Fatal("expected the logger to be replaced")
	}
}

func TestLogFailure_CoversEveryCode(t *testing.T) {
	var buffer syncBuffer
	previous := logger.Load()
	t.Cleanup(func() { SetLogger(previous) })
	SetLogger(slog.New(slog.NewTextHandler(&buffer, nil)))

	for _, failure := range []*LoginFailure{
		{Code: LoginErrorRejected, Cause: errors.New("provider said no")},
		{Code: LoginErrorExpired, Cause: ErrStateMismatch},
		{Code: LoginErrorUnavailable, Cause: ErrProviderUnavailable},
		{Code: LoginErrorFailed, Cause: errors.New("boom")},
	} {
		LogFailure(failure)
	}

	logged := buffer.String()
	for _, want := range []string{
		"level=WARN msg=\"OIDC provider rejected login\"",
		"level=WARN msg=\"OIDC login expired or state mismatch\"",
		"level=ERROR msg=\"OIDC provider unavailable\"",
		"level=ERROR msg=\"OIDC login failed\"",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("expected %q in the log output", want)
		}
	}
}

func TestLogFailure_IgnoresNil(t *testing.T) {
	LogFailure(nil)
}

type syncBuffer struct {
	mu  sync.Mutex
	raw bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.raw.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.raw.String()
}
