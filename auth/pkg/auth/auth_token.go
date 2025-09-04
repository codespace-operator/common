package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
	ErrNoToken      = errors.New("no token provided")
)

// TokenManager handles JWT creation and validation
type TokenManager interface {
	CreateToken(subject string, roles []string, provider string, ttl time.Duration, extras map[string]any) (string, error)
	ValidateToken(token string) (*TokenClaims, error)
	RefreshToken(token string, ttl time.Duration) (string, error)
}

// JWTManager implements TokenManager interface
type JWTManager struct {
	secret []byte
	logger *slog.Logger
}

type TokenClaims struct {
	Username  string   `json:"username,omitempty"`
	Sub       string   `json:"sub"`             // Reliable
	Roles     []string `json:"roles,omitempty"` // mapped from OIDC groups
	Email     string   `json:"email,omitempty"`
	Provider  string   `json:"provider,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// NewJWTManager creates a new JWT token manager
func NewJWTManager(secret string, logger *slog.Logger) (TokenManager, error) {
	if secret == "" {
		return nil, errors.New("JWT secret cannot be empty")
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &JWTManager{
		secret: []byte(secret),
		logger: logger.With("component", "jwt"),
	}, nil
}

// CreateToken creates a new JWT token with the specified claims
func (j *JWTManager) CreateToken(subject string, roles []string, provider string, ttl time.Duration, extras map[string]any) (string, error) {
	if subject == "" {
		return "", errors.New("subject cannot be empty")
	}

	if ttl == 0 {
		ttl = time.Hour // Default to 1 hour
	}

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	now := time.Now()
	claims := map[string]any{
		"sub":      subject,
		"roles":    roles,
		"provider": provider,
		"iat":      now.Unix(),
		"exp":      now.Add(ttl).Unix(),
	}

	// Add extra claims
	for k, v := range extras {
		claims[k] = v
	}

	// Encode header and payload
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create signature
	message := encodedHeader + "." + encodedPayload
	signature := j.sign(message)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	token := message + "." + encodedSignature

	j.logger.Debug("Created JWT token",
		"subject", subject,
		"provider", provider,
		"expires", now.Add(ttl))

	return token, nil
}

// ValidateToken validates a JWT token and returns the claims
func (j *JWTManager) ValidateToken(token string) (*TokenClaims, error) {
	if token == "" {
		return nil, ErrNoToken
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		j.logger.Debug("Invalid token format", "parts", len(parts))
		return nil, ErrInvalidToken
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		j.logger.Debug("Failed to decode signature", "error", err)
		return nil, ErrInvalidToken
	}

	expectedSignature := j.sign(message)
	if subtle.ConstantTimeCompare(signature, expectedSignature) != 1 {
		j.logger.Debug("Signature verification failed")
		return nil, ErrInvalidToken
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		j.logger.Debug("Failed to decode payload", "error", err)
		return nil, ErrInvalidToken
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		j.logger.Debug("Failed to unmarshal claims", "error", err)
		return nil, ErrInvalidToken
	}

	// Check expiration
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		j.logger.Debug("Token expired", "exp", claims.ExpiresAt, "now", time.Now().Unix())
		return nil, ErrExpiredToken
	}

	j.logger.Debug("Validated JWT token", "subject", claims.Sub, "provider", claims.Provider)

	return &claims, nil
}

// RefreshToken creates a new token with extended expiration based on existing token
func (j *JWTManager) RefreshToken(token string, ttl time.Duration) (string, error) {
	claims, err := j.ValidateToken(token)
	if err != nil {
		return "", fmt.Errorf("cannot refresh invalid token: %w", err)
	}

	// Create new token with same claims but new expiration
	extras := make(map[string]any)
	if claims.Email != "" {
		extras["email"] = claims.Email
	}
	if claims.Username != "" {
		extras["username"] = claims.Username
	}

	return j.CreateToken(claims.Sub, claims.Roles, claims.Provider, ttl, extras)
}
