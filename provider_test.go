package gosso

import (
	"context"
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
		default:
			claims := fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":%q,"exp":%d}`,
				server.URL, testConfig().ClientID, code, time.Now().Add(time.Hour).Unix())
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

func fakeProviderConfig(server *httptest.Server) Config {
	config := testConfig()
	config.IssuerURL = server.URL

	return config
}

func TestProvider_ExchangeReturnsTheSubject(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	provider := NewProvider(func() Config { return config })

	subject, err := provider.Exchange(context.Background(), config, "user-123", "verifier", server.URL+"/auth/callback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "user-123" {
		t.Fatalf("subject = %q, want %q", subject, "user-123")
	}
}

func TestProvider_ExchangeFailsWithoutIDToken(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	provider := NewProvider(func() Config { return config })

	if _, err := provider.Exchange(context.Background(), config, "no-id-token", "verifier", server.URL+"/auth/callback"); err == nil {
		t.Fatal("expected an error when the provider omits the id_token")
	}
}

func TestProvider_ExchangeFailsOnUnverifiableIDToken(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	provider := NewProvider(func() Config { return config })

	if _, err := provider.Exchange(context.Background(), config, "bad-id-token", "verifier", server.URL+"/auth/callback"); err == nil {
		t.Fatal("expected an error for an unverifiable id_token")
	}
}

func TestProvider_ExchangeFailsWhenProviderUnavailable(t *testing.T) {
	config := testConfig()
	provider := NewProvider(func() Config { return config })

	if _, err := provider.Exchange(context.Background(), config, "code", "verifier", testIssuer+"/auth/callback"); err == nil {
		t.Fatal("expected an error when the provider is unreachable")
	}
}

func TestProvider_ResolveCachesDiscoveredState(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	provider := NewProvider(func() Config { return config })

	first, err := provider.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	second, err := provider.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first != second {
		t.Fatal("expected the discovered state to be reused for an unchanged issuer")
	}

	config.IssuerURL = "https://other.example.com"
	if _, err := provider.resolve(); err == nil {
		t.Fatal("expected a rediscovery attempt after the issuer changed")
	}
}

func TestProvider_LoginUsesTheConfiguredSecret(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	provider := NewProvider(func() Config { return config })

	login, err := provider.Login(config, server.URL+"/auth/callback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if login.ClientSecret != config.ClientSecret {
		t.Fatalf("ClientSecret = %q, want %q", login.ClientSecret, config.ClientSecret)
	}
	if login.RedirectURL != server.URL+"/auth/callback" {
		t.Fatalf("RedirectURL = %q", login.RedirectURL)
	}
}

func TestRandomToken_ReturnsHexOfRequestedSize(t *testing.T) {
	token, err := RandomToken(stateTokenSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != stateTokenSize*2 {
		t.Fatalf("len(token) = %d, want %d", len(token), stateTokenSize*2)
	}
}

func TestProvider_ResolveDiscoversTheProvider(t *testing.T) {
	server := newFakeProvider(t)
	config := fakeProviderConfig(server)
	provider := NewProvider(func() Config { return config })

	resolved, err := provider.Resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resolved {
		t.Fatal("expected Resolve to report success")
	}
	if !provider.Resolved() {
		t.Fatal("expected the provider to be resolved")
	}
}

func TestProvider_ResolveReportsUnreachableProvider(t *testing.T) {
	config := testConfig()
	provider := NewProvider(func() Config { return config })

	resolved, err := provider.Resolve()
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
	if resolved {
		t.Fatal("expected Resolve to report failure")
	}
	if provider.Resolved() {
		t.Fatal("expected the provider not to be resolved after a failure")
	}
}
