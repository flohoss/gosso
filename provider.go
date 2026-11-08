package gosso

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DiscoveryTimeout bounds a single OIDC discovery attempt.
const DiscoveryTimeout = 10 * time.Second

// Provider caches OIDC discovery for the configured issuer and client ID.
type Provider struct {
	mu        sync.Mutex
	state     *providerState
	issuerURL string
	clientID  string
	secret    string
	scopes    []string
}

type providerState struct {
	verifier *oidc.IDTokenVerifier
	config   oauth2.Config
}

// RandomToken returns a cryptographically random text token; state tokens for
// OAuth2 redirects and session identifiers use it.
func RandomToken() string {
	return rand.Text()
}

func newProvider(opts Options) *Provider {
	return &Provider{
		issuerURL: opts.IssuerURL,
		clientID:  opts.ClientID,
		secret:    opts.ClientSecret,
		scopes:    opts.Scopes,
	}
}

// Warm starts discovery in the background so the first login request does not pay for it.
func (p *Provider) Warm() {
	go func() {
		_, _ = p.Resolve()
	}()
}

// Resolved reports whether provider discovery has already completed successfully.
func (p *Provider) Resolved() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.state != nil
}

// Resolve resolves the provider now and reports whether discovery succeeded.
func (p *Provider) Resolve() (bool, error) {
	_, err := p.resolve()

	return err == nil, err
}

// resolve returns the cached provider state, rediscovering only after a reset.
// Discovery failures are not cached and are retried on the next call.
func (p *Provider) resolve() (*providerState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != nil {
		return p.state, nil
	}

	state, err := p.discover()
	if err != nil {
		return nil, err
	}
	p.state = state

	return state, nil
}

func (p *Provider) discover() (*providerState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, p.issuerURL)
	if err != nil {
		logger.Load().Warn("OIDC discovery failed, will retry on the next request", "issuer", p.issuerURL, "error", err)

		return nil, fmt.Errorf("%w: discovery for %q failed: %w", ErrProviderUnavailable, p.issuerURL, err)
	}

	scopes := p.scopes

	logger.Load().Info("SSO provider discovered", "issuer", p.issuerURL)

	return &providerState{
		verifier: provider.Verifier(&oidc.Config{
			ClientID: p.clientID,
		}),
		config: oauth2.Config{
			ClientID: p.clientID,
			Endpoint: provider.Endpoint(),
			Scopes:   scopes,
		},
	}, nil
}

// oauthConfig returns the cached discovery config with the secret and the
// redirect URI filled in, plus the verifier matching the discovery key set.
func (p *Provider) oauthConfig(redirectURL string) (oauth2.Config, *oidc.IDTokenVerifier, error) {
	state, err := p.resolve()
	if err != nil {
		return oauth2.Config{}, nil, err
	}

	login := state.config
	login.ClientSecret = p.secret
	login.RedirectURL = redirectURL

	return login, state.verifier, nil
}

// exchange redeems the code with PKCE, verifies the id_token and returns its subject.
func (p *Provider) exchange(ctx context.Context, code, verifier, redirectURL string) (string, error) {
	login, idTokenVerifier, err := p.oauthConfig(redirectURL)
	if err != nil {
		return "", err
	}

	token, err := login.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", errors.New("OIDC provider did not return an id_token")
	}

	idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("failed to verify id_token: %w", err)
	}

	if idToken.Subject == "" {
		return "", errors.New("OIDC provider returned an id_token without a subject")
	}

	return idToken.Subject, nil
}
