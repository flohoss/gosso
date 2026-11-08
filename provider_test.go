package gosso

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

const (
	testKeyID  = "test-key"
	testIssuer = "https://issuer.example.com"
)

func newFakeProvider(t *testing.T) *httptest.Server {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate a test key: %v", err)
	}

	oidcServer := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{
			PublicKey: privateKey.Public(),
			KeyID:     testKeyID,
			Algorithm: oidc.RS256,
		}},
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	oidcServer.SetIssuer(server.URL)

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch code := r.Form.Get("code"); code {
		case "no-id-token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer"})
		case "bad-id-token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": "not-a-jwt"})
		case "no-subject":
			claims := fmt.Sprintf(`{"iss":%q,"aud":%q,"exp":%d}`,
				server.URL, testOptions().ClientID, time.Now().Add(time.Hour).Unix())
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access",
				"token_type":   "Bearer",
				"id_token":     oidctest.SignIDToken(privateKey, testKeyID, oidc.RS256, claims),
			})
		case "invalid-code":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
		default:
			claims := fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":%q,"exp":%d}`,
				server.URL, testOptions().ClientID, code, time.Now().Add(time.Hour).Unix())
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access",
				"token_type":   "Bearer",
				"id_token":     oidctest.SignIDToken(privateKey, testKeyID, oidc.RS256, claims),
			})
		}
	})
	mux.Handle("/", oidcServer)

	return server
}

func newTestAuthForProvider(t *testing.T, server *httptest.Server) *Auth {
	t.Helper()

	opts := testOptions()
	opts.IssuerURL = server.URL
	opts.DB = newTestDB(t)

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	return auth
}

func TestProvider_ResolveDiscoversTheProvider(t *testing.T) {
	auth := newTestAuthForProvider(t, newFakeProvider(t))

	resolved, err := auth.Provider().Resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resolved || !auth.Provider().Resolved() {
		t.Fatal("expected the provider to be resolved")
	}
}

func TestProvider_ResolveReportsUnreachableProvider(t *testing.T) {
	auth := newTestAuth(t)

	resolved, err := auth.Provider().Resolve()
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
	if resolved || auth.Provider().Resolved() {
		t.Fatal("expected the provider not to be resolved after a failure")
	}
}

func TestProvider_ResolveRetriesAfterAFailure(t *testing.T) {
	opts := testOptions()
	opts.DB = newTestDB(t)

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}

	if _, err := auth.Provider().Resolve(); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected the first resolve to fail, got %v", err)
	}

	if _, err := auth.Provider().Resolve(); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected the failed discovery not to be cached, got %v", err)
	}
}

func TestProvider_ResolveCachesTheFirstState(t *testing.T) {
	auth := newTestAuthForProvider(t, newFakeProvider(t))

	first, err := auth.provider.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	second, err := auth.provider.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first != second {
		t.Fatal("expected the discovered state to be reused")
	}
}

func TestProvider_ExchangeReturnsTheSubject(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	subject, err := auth.provider.exchange(t.Context(), "user-123", "verifier", server.URL+CallbackRoute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "user-123" {
		t.Fatalf("subject = %q, want %q", subject, "user-123")
	}
}

func TestProvider_ExchangeFailsWithoutIDToken(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	if _, err := auth.provider.exchange(t.Context(), "no-id-token", "verifier", server.URL+CallbackRoute); err == nil {
		t.Fatal("expected an error when the provider omits the id_token")
	}
}

func TestProvider_ExchangeFailsOnUnverifiableIDToken(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	if _, err := auth.provider.exchange(t.Context(), "bad-id-token", "verifier", server.URL+CallbackRoute); err == nil {
		t.Fatal("expected an error for an unverifiable id_token")
	}
}

func TestProvider_LoginUsesTheConfiguredSecret(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	login, _, err := auth.provider.oauthConfig(server.URL + CallbackRoute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if login.ClientSecret != testOptions().ClientSecret {
		t.Fatalf("ClientSecret = %q", login.ClientSecret)
	}
	if login.RedirectURL != server.URL+CallbackRoute {
		t.Fatalf("RedirectURL = %q", login.RedirectURL)
	}
}

func TestRandomToken_ReturnsDistinctTextTokens(t *testing.T) {
	first := RandomToken()
	second := RandomToken()

	if first == "" || second == "" {
		t.Fatal("expected non-empty tokens")
	}
	if first == second {
		t.Fatal("expected independent tokens")
	}
}

func TestProvider_WarmResolvesInBackground(t *testing.T) {
	auth := newTestAuthForProvider(t, newFakeProvider(t))
	auth.provider.Warm()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if auth.Provider().Resolved() {
			return
		}
		time.Sleep(time.Millisecond)
	}

	t.Fatal("expected Warm to resolve the provider in the background")
}

func TestProvider_ExchangeFailsWhenDiscoveryIsUnresolved(t *testing.T) {
	auth := newTestAuth(t)

	if _, err := auth.provider.exchange(t.Context(), "code", "verifier", "https://app/callback"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
}

func TestProvider_ExchangeFailsWhenTheTokenEndpointRejectsTheCode(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	if _, err := auth.provider.exchange(t.Context(), "invalid-code", "verifier", server.URL+CallbackRoute); err == nil {
		t.Fatal("expected the token endpoint to reject an unknown code")
	}
}

func TestProvider_ExchangeFailsWithoutASubject(t *testing.T) {
	server := newFakeProvider(t)
	auth := newTestAuthForProvider(t, server)

	if _, err := auth.provider.exchange(t.Context(), "no-subject", "verifier", server.URL+CallbackRoute); err == nil {
		t.Fatal("expected an error for an id_token without a subject")
	}
}
