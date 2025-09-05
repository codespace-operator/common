package auth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	OIDC_PROVIDER   = "oidc"
	OIDCStateCookie = "oidc_state"
	OIDCNonceCookie = "oidc_nonce"
	OIDCPKCECookie  = "oidc_pkce"
)

type OIDCConfig struct {
	Enabled            bool
	IssuerURL          string
	ClientID           string
	ClientSecret       string
	RedirectURL        string
	Scopes             []string
	InsecureSkipVerify bool
}

// OIDCProvider implements AuthProvider interface for OIDC authentication
type OIDCProvider struct {
	ProviderBase
	config       *OIDCConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	httpClient   *http.Client
	endSession   string
	issuerID     string
}

// NewOIDCProvider creates a new OIDC authentication provider
func NewOIDCProvider(config *OIDCConfig, tokenManager TokenManager, logger *slog.Logger, authManagerParent *AuthManager) (*OIDCProvider, error) {
	if logger == nil {
		logger = slog.Default()
	}

	logger = logger.With("component", OIDC_PROVIDER)

	ctx := context.Background()

	// Setup HTTP client for insecure connections if needed
	var httpClient *http.Client
	if config.InsecureSkipVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient = &http.Client{Transport: tr, Timeout: 15 * time.Second}
		logger.Warn("OIDC InsecureSkipVerify is enabled - do not use in production")
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	// Initialize OIDC provider
	logger.Info("Initializing OIDC provider", "issuer", config.IssuerURL)
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		logger.Error("Failed to initialize OIDC provider", "error", err)
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Setup ID token verifier
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	// Setup OAuth2 configuration
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       scopes,
	}

	// Get provider metadata for logout endpoint
	var metadata struct {
		Issuer             string `json:"issuer"`
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&metadata)

	issuer := metadata.Issuer
	if issuer == "" {
		issuer = config.IssuerURL
	}

	return &OIDCProvider{
		ProviderBase: NewProviderBase(tokenManager, logger, authManagerParent),
		config:       config,
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
		httpClient:   httpClient,
		endSession:   metadata.EndSessionEndpoint,
		issuerID:     issuerIDFromURL(issuer),
	}, nil
}

// Name returns the provider name
func (o *OIDCProvider) Name() string {
	return OIDC_PROVIDER
}

// StartAuth initiates OIDC authentication flow
func (o *OIDCProvider) StartAuth(w http.ResponseWriter, r *http.Request, redirectAfter string) error {
	state := generateRandomString(32)
	nonce := generateRandomString(32)
	verifier, challenge := generatePKCEPair()

	// Store temporary values in cookies
	o.authManagerParent.SetCookie(w, r, OIDCStateCookie, state, CookieTempAuth, nil)
	o.authManagerParent.SetCookie(w, r, OIDCNonceCookie, nonce, CookieTempAuth, nil)
	o.authManagerParent.SetCookie(w, r, OIDCPKCECookie, verifier, CookieTempAuth, nil)

	// Encode redirect path in state if provided
	if redirectAfter != "" && isSafeRedirect(redirectAfter) {
		encodedRedirect := base64.RawURLEncoding.EncodeToString([]byte(redirectAfter))
		state = state + "|" + encodedRedirect
	}

	// Build authorization URL
	authURL := o.oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.AccessTypeOffline,
	)

	o.logger.Debug("Starting OIDC auth flow", "redirect_after", redirectAfter)
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

// HandleCallback processes OIDC callback and returns user claims
func (o *OIDCProvider) HandleCallback(w http.ResponseWriter, r *http.Request) (*TokenClaims, error) {
	// ... verify state/nonce/PKCE, exchange, verify id_token ...
	// create canonical subject, set id_token_hint, clear temp cookies
	// build and return claims ONLY (no JWT mint, no session cookie)
	// Handle session cookies in AuthManager
	query := r.URL.Query()

	// Verify state parameter
	gotState := query.Get("state")
	if gotState == "" {
		return nil, fmt.Errorf("missing state parameter")
	}

	stateCookie, err := r.Cookie(OIDCStateCookie)
	if err != nil || stateCookie.Value == "" {
		return nil, fmt.Errorf("missing state cookie")
	}

	// Extract original state and redirect path
	rawState := gotState
	var redirectAfter string
	if parts := strings.SplitN(gotState, "|", 2); len(parts) == 2 {
		rawState = parts[0]
		if decoded, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			redirectAfter = string(decoded)
		}
	}

	if !constantTimeEqual(rawState, stateCookie.Value) {
		return nil, fmt.Errorf("state mismatch")
	}

	// Get PKCE verifier
	pkceCookie, err := r.Cookie(OIDCPKCECookie)
	if err != nil || pkceCookie.Value == "" {
		return nil, fmt.Errorf("missing PKCE cookie")
	}

	// Exchange authorization code for tokens
	code := query.Get("code")
	if code == "" {
		return nil, fmt.Errorf("missing authorization code")
	}

	ctx := r.Context()
	if o.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	}

	token, err := o.oauth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pkceCookie.Value))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract and verify ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("no id_token in response")
	}

	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token: %w", err)
	}

	// Verify nonce
	nonceCookie, err := r.Cookie(OIDCNonceCookie)
	if err != nil || nonceCookie.Value == "" {
		return nil, fmt.Errorf("missing nonce cookie")
	}

	var idClaims struct {
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name"`
		Username      string   `json:"preferred_username"`
		Groups        []string `json:"groups"`
		Roles         []string `json:"roles"`
		Nonce         string   `json:"nonce"`
	}

	if err := idToken.Claims(&idClaims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	if idClaims.Nonce != "" && idClaims.Nonce != nonceCookie.Value {
		return nil, fmt.Errorf("nonce mismatch")
	}

	// Map groups to roles if roles are not directly provided
	roles := idClaims.Roles
	if len(roles) == 0 && len(idClaims.Groups) > 0 {
		roles = idClaims.Groups
	}

	// Create canonical subject identifier
	canonicalSubject := OIDC_PROVIDER + ":" + o.issuerID + ":" + idToken.Subject

	// Store ID token for logout (tight scope + short TTL via CookieLogoutHint)
	o.authManagerParent.SetCookie(w, r, "oidc_id_token_hint", rawIDToken, CookieLogoutHint, nil)

	o.authManagerParent.ClearCookie(w, OIDCStateCookie, CookieTempAuth)
	o.authManagerParent.ClearCookie(w, OIDCNonceCookie, CookieTempAuth)
	o.authManagerParent.ClearCookie(w, OIDCPKCECookie, CookieTempAuth)

	// Create token claims
	claims := &TokenClaims{
		Sub:       canonicalSubject,
		Username:  idClaims.Username,
		Email:     idClaims.Email,
		Roles:     roles,
		Provider:  OIDC_PROVIDER,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: 0, // server (AuthManager) owns TTL
	}

	o.logger.Info("OIDC authentication successful",
		"subject", idToken.Subject,
		"email", idClaims.Email,
		"roles", roles)

	// Handle redirect if specified
	if redirectAfter != "" && isSafeRedirect(redirectAfter) {
		// Short-lived temp cookie for the redirect hint (TempAuth profile).
		o.authManagerParent.SetCookie(w, r, "post_auth_redirect", redirectAfter, CookieTempAuth, nil)
	}
	return claims, nil
}

// Logout handles OIDC logout flow
func (o *OIDCProvider) Logout(w http.ResponseWriter, r *http.Request) error {
	// Clear any provider-specific cookies/state
	o.authManagerParent.ClearAuthCookie(w)

	// Redirect to provider's logout endpoint if available
	if o.endSession != "" {
		var hint string
		if c, err := r.Cookie("oidc_id_token_hint"); err == nil {
			hint = c.Value
		}
		o.authManagerParent.ClearCookie(w, "oidc_id_token_hint", CookieLogoutHint)
		logoutURL := o.endSession
		if o.config.RedirectURL != "" {
			logoutURL += "?post_logout_redirect_uri=" + url.QueryEscape(o.config.RedirectURL)
			if hint != "" {
				logoutURL += "&id_token_hint=" + url.QueryEscape(hint)
			}
		}

		o.logger.Debug("Redirecting to OIDC logout", "url", logoutURL)
		http.Redirect(w, r, logoutURL, http.StatusFound)
		return nil
	}

	o.logger.Debug("No OIDC logout endpoint configured, logout completed locally")
	return nil
}

// ValidateToken validates a token (delegates to token manager)
func (o *OIDCProvider) ValidateToken(token string) (*TokenClaims, error) {
	return o.tokenManager.ValidateToken(token)
}
