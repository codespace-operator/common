package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Context key for storing authentication claims
type contextKey struct {
	name string
}

var (
	claimsKey = &contextKey{"claims"}
)

const (
	defaultSessionCookieName = "you_should_change_me"
	defaultSameSiteMode      = http.SameSiteStrictMode
)

type Manager interface {
	// request validation
	ValidateRequest(r *http.Request) (*TokenClaims, error)

	// provider access
	GetProvider(name string) Provider
	GetLocalProvider() LocalAuthProvider
	ListProviders() []string
	GetTokenManager() TokenManager

	// session helpers
	SetAuthCookie(w http.ResponseWriter, r *http.Request, token string)
	SetCookie(w http.ResponseWriter, r *http.Request, name, value string, kind CookieKind, override *CookieOpts)
	ClearCookie(w http.ResponseWriter, name string, kind CookieKind)
	ClearAuthCookie(w http.ResponseWriter)
	IssueSession(w http.ResponseWriter, r *http.Request, claims *TokenClaims) (string, error)
	GetAuthPath() string
	GetAuthLogoutPath() string
	GetCookieName() string
}

type AuthManager struct {
	providers    map[string]Provider
	tokenManager TokenManager
	config       *AuthConfig
	logger       *slog.Logger
}

// compile-time check: concrete matches interface
var _ Manager = (*AuthManager)(nil)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWTSecret          string
	SessionCookieName  string
	SessionTTL         time.Duration
	AllowTokenParam    bool
	SameSiteMode       http.SameSite
	AbsoluteSessionMax time.Duration
	AuthPath           string
	AuthLogoutPath     string
	// OIDC Configuration
	OIDC *OIDCConfig

	// Local Authentication Configuration
	Local *LocalConfig

	// LDAP Authentication Configuration
	LDAP *LDAPConfig
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cfg *AuthConfig, logger *slog.Logger) (*AuthManager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = time.Hour
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = defaultSessionCookieName
	}
	if cfg.SameSiteMode == 0 {
		cfg.SameSiteMode = defaultSameSiteMode
	}
	if cfg.AuthPath == "" {
		cfg.AuthPath = "/auth"
	}
	if cfg.AuthLogoutPath == "" {
		cfg.AuthLogoutPath = "/auth/logout"
	}
	if cfg.AbsoluteSessionMax == 0 {
		cfg.AbsoluteSessionMax = 24 * time.Hour
	}

	tm, err := NewJWTManager(cfg.JWTSecret, logger)
	if err != nil {
		return nil, err
	}
	am := &AuthManager{
		providers:    make(map[string]Provider),
		tokenManager: tm,
		config:       cfg,
		logger:       logger,
	}
	if err := am.initializeProviders(); err != nil {
		return nil, err
	}
	return am, nil
}

func (am *AuthManager) GetAuthPath() string {
	return am.config.AuthPath
}

func (am *AuthManager) GetAuthLogoutPath() string {
	return am.config.AuthLogoutPath
}

func (am *AuthManager) GetCookieName() string {
	return am.config.SessionCookieName
}

func (am *AuthManager) GetProvider(name string) Provider {
	return am.providers[name]
}

func (am *AuthManager) GetLocalProvider() LocalAuthProvider {
	if p, ok := am.providers[LOCAL_PROVIDER].(LocalAuthProvider); ok {
		return p
	}
	// Signals LocalAuth was disabled.
	return nil
}

func (am *AuthManager) ListProviders() []string {
	out := make([]string, 0, len(am.providers))
	for name := range am.providers {
		out = append(out, name)
	}
	return out
}

// initializeProviders sets up authentication providers based on config
func (am *AuthManager) initializeProviders() error {
	// Initialize OIDC provider if configured
	if am.config.OIDC != nil && am.config.OIDC.IssuerURL != "" && am.config.OIDC.Enabled {
		oidcProvider, err := NewOIDCProvider(am.config.OIDC, am.tokenManager, am.logger, am)
		if err != nil {
			am.logger.Error("Failed to initialize OIDC provider", "error", err)
			return err
		}
		am.providers[OIDC_PROVIDER] = oidcProvider
		am.logger.Info("OIDC authentication provider initialized", "issuer", am.config.OIDC.IssuerURL)
	}

	// Initialize local provider if configured
	if am.config.Local != nil && am.config.Local.Enabled {
		localProvider, err := NewLocalProvider(am.config.Local, am.tokenManager, am.logger, am)
		if err != nil {
			am.logger.Error("Failed to initialize local provider", "error", err)
			return err
		}
		am.providers[LOCAL_PROVIDER] = localProvider
		am.logger.Info("Local authentication provider initialized")
	}

	if len(am.providers) == 0 {
		am.logger.Warn("No authentication providers configured")
	}
	// Initialize LDAP provider if configured
	if am.config.LDAP != nil && am.config.LDAP.Enabled {
		lp, err := NewLDAPProvider(am.config.LDAP, am.tokenManager, am.logger, am)
		if err != nil {
			am.logger.Error("Failed to initialize LDAP provider", "error", err)
			return err
		}
		am.providers[LDAP_PROVIDER] = lp
		am.logger.Info("LDAP authentication provider initialized", "url", am.config.LDAP.URL)
	}

	return nil
}

// GetProvider returns the token manager
func (am *AuthManager) GetTokenManager() TokenManager {
	return am.tokenManager
}

// GetProvider returns the LDAPProvider
func (am *AuthManager) GetLDAPProvider() LDAPAuthProvider {
	if p, ok := am.providers[LDAP_PROVIDER].(LDAPAuthProvider); ok {
		return p
	}
	return nil
}

// ValidateRequest validates authentication from HTTP request
func (am *AuthManager) ValidateRequest(r *http.Request) (*TokenClaims, error) {
	token, err := am.extractToken(r)
	if err != nil {
		return nil, err
	}

	return am.tokenManager.ValidateToken(token)
}

// extractToken extracts token from various sources (cookie, header, query param)
func (am *AuthManager) extractToken(r *http.Request) (string, error) {
	// Reuse the shared helper; it already handles cookie/header/param.
	return ExtractTokenFromRequest(r, am.config.SessionCookieName, am.config.AllowTokenParam)
}

// SetAuthCookie sets authentication cookie
func (am *AuthManager) SetAuthCookie(w http.ResponseWriter, r *http.Request, token string) {
	am.SetCookie(w, r, am.config.SessionCookieName, token, CookieSession, nil)
}

// ClearAuthCookie clears the authentication cookie
func (am *AuthManager) ClearAuthCookie(w http.ResponseWriter) {
	am.ClearCookie(w, am.config.SessionCookieName, CookieSession)
}

// IssueSession creates a new session for the user
func (am *AuthManager) IssueSession(w http.ResponseWriter, r *http.Request, c *TokenClaims) (string, error) {
	if c == nil || c.Sub == "" {
		return "", errors.New("empty claims")
	}
	ttl := am.config.SessionTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	token, err := am.tokenManager.CreateToken(
		c.Sub, c.Roles, c.Provider, ttl,
		map[string]any{
			"email":    c.Email,
			"username": c.Username,
		},
	)
	if err != nil {
		return "", err
	}
	am.SetAuthCookie(w, r, token)
	return token, nil
}

// WithClaims adds token claims to the context
func WithClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// FromContext retrieves token claims from the context
func FromContext(r *http.Request) *TokenClaims {
	if claims, ok := r.Context().Value(claimsKey).(*TokenClaims); ok {
		return claims
	}
	return nil
}

// ClaimsFromContext retrieves token claims from a context
func ClaimsFromContext(ctx context.Context) *TokenClaims {
	if claims, ok := ctx.Value(claimsKey).(*TokenClaims); ok {
		return claims
	}
	return nil
}

// RequireAuth extracts and validates authentication from context
func RequireAuth(ctx context.Context) (*TokenClaims, error) {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return nil, errors.New("no authentication found")
	}

	if claims.IsExpired() {
		return nil, errors.New("authentication expired")
	}

	return claims, nil
}

// OptionalAuth extracts authentication from context if present
func OptionalAuth(ctx context.Context) *TokenClaims {
	claims := ClaimsFromContext(ctx)
	if claims != nil && !claims.IsExpired() {
		return claims
	}
	return nil
}

// RequireAPIToken middleware that requires session or bearer token (legacy compatibility)
func RequireAPIToken(am Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := am.ValidateRequest(r) // cookie/header/param -> token -> ValidateToken
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}
