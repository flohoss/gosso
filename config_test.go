package gosso

import (
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestValidate_AcceptsCompleteOptions(t *testing.T) {
	if err := testOptions().Validate(); err != nil {
		t.Fatalf("expected valid options, got %v", err)
	}
}

func TestValidate_RejectsMissingOIDCFields(t *testing.T) {
	if err := (Options{Enabled: true}).Validate(); !errors.Is(err, ErrMissingOIDCFields) {
		t.Fatalf("expected ErrMissingOIDCFields, got %v", err)
	}
}

func TestValidate_RejectsTrailingSlashIssuer(t *testing.T) {
	opts := testOptions()
	opts.IssuerURL = "https://sso.example.com/"

	if err := opts.Validate(); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got %v", err)
	}
}

func TestValidate_RejectsIssuerWithoutHost(t *testing.T) {
	opts := testOptions()
	opts.IssuerURL = "sso.example.com"

	if err := opts.Validate(); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got %v", err)
	}
}

func TestValidate_RejectsUnparsableIssuer(t *testing.T) {
	opts := testOptions()
	opts.IssuerURL = "https://sso.example.com/%zz"

	if err := opts.Validate(); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got %v", err)
	}
}

func TestValidate_AcceptsAppURL(t *testing.T) {
	opts := testOptions()
	opts.AppURL = "https://app.example.com"

	if err := opts.Validate(); err != nil {
		t.Fatalf("expected a valid app_url, got %v", err)
	}
}

func TestValidate_RejectsUnparsableAppURL(t *testing.T) {
	opts := testOptions()
	opts.AppURL = "https://app.example.com/%zz"

	if err := opts.Validate(); !errors.Is(err, ErrInvalidAppURL) {
		t.Fatalf("expected ErrInvalidAppURL, got %v", err)
	}
}

func TestNew_RequiresDatabase(t *testing.T) {
	if _, err := New(testOptions()); !errors.Is(err, ErrMissingDatabase) {
		t.Fatalf("expected ErrMissingDatabase, got %v", err)
	}
}

func TestNew_ValidatesEnabledOptions(t *testing.T) {
	opts := testOptions()
	opts.ClientSecret = ""
	opts.DB = newTestDB(t)

	if _, err := New(opts); !errors.Is(err, ErrMissingOIDCFields) {
		t.Fatalf("expected ErrMissingOIDCFields, got %v", err)
	}
}

// A disabled instance must still build so an app can run without credentials and
// only needs a restart to enable SSO.
func TestNew_ToleratesMissingCredentialsWhenDisabled(t *testing.T) {
	opts := Options{DB: newTestDB(t)}

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("expected a disabled instance to build, got %v", err)
	}
	if auth.Enabled() {
		t.Fatal("expected auth to be disabled")
	}
}

func TestNew_CreatesTheSessionTable(t *testing.T) {
	db := newTestDB(t)
	opts := testOptions()
	opts.DB = db

	if _, err := New(opts); err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	if _, err := db.ExecContext(t.Context(), `SELECT 1 FROM sso_sessions`); err != nil {
		t.Fatalf("expected the sso_sessions table to exist: %v", err)
	}
}

func TestWithDefaults_FillsDerivedValues(t *testing.T) {
	filled := Options{ClientID: "My-App-Client"}.withDefaults()

	if filled.SessionTTL != DefaultSessionTTL {
		t.Fatalf("SessionTTL = %v, want %v", filled.SessionTTL, DefaultSessionTTL)
	}
	if filled.CookiePrefix != "myappclient" {
		t.Fatalf("CookiePrefix = %q, want %q", filled.CookiePrefix, "myappclient")
	}
	if filled.CookieName != "myappclient_session" {
		t.Fatalf("CookieName = %q, want %q", filled.CookieName, "myappclient_session")
	}
	if len(filled.Scopes) != 1 || filled.Scopes[0] != "openid" {
		t.Fatalf("Scopes = %v, want [openid]", filled.Scopes)
	}
}

func TestWithDefaults_KeepsProvidedValues(t *testing.T) {
	filled := Options{
		SessionTTL:   2 * time.Hour,
		Scopes:       []string{"openid", "email"},
		CookiePrefix: "custom",
		CookieName:   "custom_cookie",
	}.withDefaults()

	if filled.SessionTTL != 2*time.Hour {
		t.Fatalf("SessionTTL = %v", filled.SessionTTL)
	}
	if len(filled.Scopes) != 2 {
		t.Fatalf("Scopes = %v", filled.Scopes)
	}
	if filled.CookieName != "custom_cookie" {
		t.Fatalf("CookieName = %q", filled.CookieName)
	}
}

func TestEnabled_ToleratesNilReceiver(t *testing.T) {
	var auth *Auth

	if auth.Enabled() {
		t.Fatal("expected a nil Auth to be disabled")
	}
}

func TestLoginPageURL_BuildsErrorQuery(t *testing.T) {
	if got := LoginPageURL(""); got != "/login" {
		t.Fatalf("LoginPageURL(\"\") = %q", got)
	}
	if got := LoginPageURL(LoginErrorExpired); got != "/login?error=expired" {
		t.Fatalf("LoginPageURL(expired) = %q", got)
	}
}

func TestSessionCookieName_FollowsOptions(t *testing.T) {
	opts := testOptions()
	opts.CookieName = "custom_session"
	opts.DB = newTestDB(t)

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := auth.SessionCookieName(); got != "custom_session" {
		t.Fatalf("SessionCookieName() = %q", got)
	}
}

func TestCallbackURL_PrefersAppURL(t *testing.T) {
	opts := testOptions()
	opts.AppURL = "https://app.example.com/"
	opts.DB = newTestDB(t)

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, req := newTestContext(http.MethodGet, "http://internal:8156/api/auth/login")

	if got, want := auth.callbackURL(req), "https://app.example.com/api/auth/callback"; got != want {
		t.Fatalf("callbackURL() = %q, want %q", got, want)
	}
}

func TestCallbackURL_DerivesFromRequest(t *testing.T) {
	auth := newTestAuth(t)

	_, req := newTestContext(http.MethodGet, "https://app.example.com:8156/api/auth/login")
	req.Header.Set("X-Forwarded-Proto", "https")

	if got, want := auth.callbackURL(req), "https://app.example.com:8156/api/auth/callback"; got != want {
		t.Fatalf("callbackURL() = %q, want %q", got, want)
	}
}

func TestNew_ReportsSessionStoreFailures(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sso.sqlite"))
	if err != nil {
		t.Fatalf("failed to open the database: %v", err)
	}
	db.Close()

	opts := testOptions()
	opts.DB = db

	if _, err := New(opts); err == nil {
		t.Fatal("expected New to report a failing session store")
	}
}
