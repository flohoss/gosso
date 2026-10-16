package gosso

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
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
