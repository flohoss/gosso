package gosso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DiscoveryTimeout bounds a single OIDC discovery attempt.
const DiscoveryTimeout = 10 * time.Second

const stateTokenSize = 24

type providerState struct {
	key      string
	verifier *oidc.IDTokenVerifier
	Config   oauth2.Config
}

// Provider caches OIDC discovery for the current issuer and client ID.
type Provider struct {
	mu       sync.Mutex
	current  *providerState
	settings func() Config
}

// NewProvider returns a Provider reading its settings through the supplied function.
func NewProvider(settings func() Config) *Provider {
	return &Provider{settings: settings}
}

// Warm starts discovery in the background so the first login request does not pay for it.
func (p *Provider) Warm() {
	go func() {
		_, _ = p.resolve()
	}()
}

// resolve returns the cached provider state, rediscovering when the issuer or client ID changed.
// Discovery failures are not cached and are retried on the next call.
func (p *Provider) resolve() (*providerState, error) {
	current := p.settings()
	key := providerKey(current)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.current != nil && p.current.key == key {
		return p.current, nil
	}

	provider, err := discoverProvider(current)
	if err != nil {
		return nil, err
	}

	p.current = provider

	return provider, nil
}

func providerKey(settings Config) string {
	return settings.IssuerURL + "|" + settings.ClientID
}

func discoverProvider(settings Config) (*providerState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, settings.IssuerURL)
	if err != nil {
		logger.Load().Warn("OIDC discovery failed, will retry on the next request", "issuer", settings.IssuerURL, "error", err)
		return nil, fmt.Errorf("%w: discovery for %q failed: %w", ErrProviderUnavailable, settings.IssuerURL, err)
	}

	scopes := settings.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}

	logger.Load().Info("SSO provider discovered", "issuer", settings.IssuerURL)

	return &providerState{
		key: providerKey(settings),
		verifier: provider.Verifier(&oidc.Config{
			ClientID: settings.ClientID,
		}),
		Config: oauth2.Config{
			ClientID: settings.ClientID,
			Endpoint: provider.Endpoint(),
			Scopes:   scopes,
		},
	}, nil
}

// Login returns the oauth2.Config used to build the authorization redirect.
func (p *Provider) Login(settings Config, redirectURL string) (oauth2.Config, error) {
	state, err := p.resolve()
	if err != nil {
		return oauth2.Config{}, err
	}

	login := state.Config
	login.ClientSecret = settings.ClientSecret
	login.RedirectURL = redirectURL

	return login, nil
}

// Exchange redeems the code with PKCE, verifies the id_token and returns its subject.
func (p *Provider) Exchange(ctx context.Context, settings Config, code, verifier, redirectURL string) (string, error) {
	state, err := p.resolve()
	if err != nil {
		return "", err
	}

	login := state.Config
	login.ClientSecret = settings.ClientSecret
	login.RedirectURL = redirectURL

	token, err := login.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", errors.New("OIDC provider did not return an id_token")
	}

	idToken, err := state.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("failed to verify id_token: %w", err)
	}

	if idToken.Subject == "" {
		return "", errors.New("OIDC provider returned an id_token without a subject")
	}

	return idToken.Subject, nil
}

// RandomToken returns size cryptographically random bytes as a hex string.
func RandomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}

	return hex.EncodeToString(buffer), nil
}
