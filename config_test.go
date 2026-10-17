package gosso

import (
	"errors"
	"testing"
	"time"
)

func TestValidate_AcceptsCompleteConfig(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatalf("expected a valid config, got %v", err)
	}
}

func TestValidate_RejectsMissingOIDCFields(t *testing.T) {
	config := Config{Enabled: true}

	if err := config.Validate(); !errors.Is(err, ErrMissingOIDCFields) {
		t.Fatalf("expected ErrMissingOIDCFields, got %v", err)
	}
}

func TestValidate_RejectsTrailingSlashIssuer(t *testing.T) {
	config := testConfig()
	config.IssuerURL = "https://sso.example.com/"

	if err := config.Validate(); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got %v", err)
	}
}

func TestValidate_RejectsIssuerWithoutHost(t *testing.T) {
	config := testConfig()
	config.IssuerURL = "sso.example.com"

	if err := config.Validate(); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got %v", err)
	}
}

func TestValidate_ToleratesBareHostAppURL(t *testing.T) {
	config := testConfig()
	config.AppURL = "https://app.example.com"

	if err := config.Validate(); err != nil {
		t.Fatalf("expected a valid app_url, got %v", err)
	}
}

func TestValidate_RejectsUnparsableIssuer(t *testing.T) {
	config := testConfig()
	config.IssuerURL = "https://sso.example.com/%zz"

	if err := config.Validate(); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer for an unparsable issuer, got %v", err)
	}
}

func TestValidate_RejectsUnparsableAppURL(t *testing.T) {
	config := testConfig()
	config.AppURL = "https://app.example.com/%zz"

	if err := config.Validate(); err == nil {
		t.Fatal("expected an error for an unparsable app_url")
	}
}

func TestValidate_RejectsShortSessionKey(t *testing.T) {
	config := testConfig()
	config.SessionKey = "too-short"

	if err := config.Validate(); !errors.Is(err, ErrInvalidSessionKey) {
		t.Fatalf("expected ErrInvalidSessionKey, got %v", err)
	}
}

func TestValidate_ToleratesEmptySessionKey(t *testing.T) {
	config := testConfig()
	config.SessionKey = ""

	if err := config.Validate(); err != nil {
		t.Fatalf("expected an empty session key to be allowed, got %v", err)
	}
}

func TestEffectiveSessionTTL_FallsBackToDefault(t *testing.T) {
	if got := (Config{}).EffectiveSessionTTL(); got != DefaultSessionTTL {
		t.Fatalf("expected the default TTL, got %v", got)
	}

	config := Config{SessionTTL: 2 * time.Hour}
	if got := config.EffectiveSessionTTL(); got != 2*time.Hour {
		t.Fatalf("expected the configured TTL, got %v", got)
	}
}

func TestWithDefaults_FillsSessionTTLAndScopes(t *testing.T) {
	filled := Config{IssuerURL: "https://sso.example.com"}.WithDefaults()

	if filled.SessionTTL != DefaultSessionTTL {
		t.Fatalf("expected %v, got %v", DefaultSessionTTL, filled.SessionTTL)
	}
	if len(filled.Scopes) != 1 || filled.Scopes[0] != "openid" {
		t.Fatalf("expected the openid scope, got %v", filled.Scopes)
	}
}

func TestWithDefaults_KeepsExistingValues(t *testing.T) {
	filled := Config{
		SessionTTL: 2 * time.Hour,
		Scopes:     []string{"openid", "email"},
	}.WithDefaults()

	if filled.SessionTTL != 2*time.Hour {
		t.Fatalf("expected the provided TTL to survive, got %v", filled.SessionTTL)
	}
	if len(filled.Scopes) != 2 {
		t.Fatalf("expected the provided scopes to survive, got %v", filled.Scopes)
	}
}
