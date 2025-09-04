package auth

import (
	"log/slog"
	"net/http"
)

// behavior that all auth providers implement
type Provider interface {
	Name() string
	StartAuth(w http.ResponseWriter, r *http.Request, redirectAfter string) error
	HandleCallback(w http.ResponseWriter, r *http.Request) (*TokenClaims, error)
	Logout(w http.ResponseWriter, r *http.Request) error
	ValidateToken(token string) (*TokenClaims, error)
}

// common fields for providers
type ProviderBase struct {
	tokenManager      TokenManager
	logger            *slog.Logger
	authManagerParent *AuthManager
}

func NewProviderBase(tokenManager TokenManager, logger *slog.Logger, authManagerParent *AuthManager) ProviderBase {
	return ProviderBase{
		tokenManager:      tokenManager,
		logger:            logger,
		authManagerParent: authManagerParent,
	}
}
