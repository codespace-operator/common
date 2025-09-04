package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	LOCAL_PROVIDER = "local"
)

// Local provider adds password auth
type LocalAuthProvider interface {
	Provider
	Authenticate(username, password string) (*TokenClaims, error)
}

// LocalProvider implements LocalAuthProvider interface
type LocalProvider struct {
	ProviderBase
	// LocalConfig contains list of local users
	config *LocalConfig
	users  *LocalUsers

	// Bootstrap user configuration
	bootstrapLoginAllowed bool
	bootstrapUser         string
	bootstrapPasswd       string
}

// LocalConfig holds local authentication configuration
type LocalConfig struct {
	Enabled               bool
	UsersPath             string
	BootstrapLoginAllowed bool
	BootstrapUser         string
	BootstrapPasswd       string
}

// LocalUser represents a local user account
type LocalUser struct {
	Username     string   `json:"username" yaml:"username"`
	PasswordHash string   `json:"passwordHash" yaml:"passwordHash"`
	Email        string   `json:"email,omitempty" yaml:"email,omitempty"`
	Roles        []string `json:"roles,omitempty" yaml:"roles,omitempty"`
}

// LocalUsers manages local user accounts
type LocalUsers struct {
	mu       sync.RWMutex
	users    map[string]LocalUser
	filePath string
	logger   *slog.Logger
}

// LoadLocalUsers loads users from file
func LoadLocalUsers(filePath string, logger *slog.Logger) (*LocalUsers, error) {
	if logger == nil {
		logger = slog.Default()
	}

	logger = logger.With("component", "local-users")

	lu := &LocalUsers{
		users:    make(map[string]LocalUser),
		filePath: filePath,
		logger:   logger,
	}

	if filePath == "" {
		logger.Info("No local users file specified")
		return lu, nil
	}

	if err := lu.loadFromFile(); err != nil {
		return nil, err
	}

	logger.Info("Local users loaded", "count", len(lu.users))
	return lu, nil
}

// loadFromFile loads users from the specified file
func (lu *LocalUsers) loadFromFile() error {
	data, err := os.ReadFile(lu.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			lu.logger.Warn("Local users file does not exist", "path", lu.filePath)
			return nil
		}
		return fmt.Errorf("failed to read local users file: %w", err)
	}

	var wrapper struct {
		Users []LocalUser `json:"users" yaml:"users"`
	}

	// Try YAML first, then JSON
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		if jsonErr := json.Unmarshal(data, &wrapper); jsonErr != nil {
			return fmt.Errorf("failed to parse local users file (tried YAML and JSON): %w", err)
		}
	}

	lu.mu.Lock()
	defer lu.mu.Unlock()

	lu.users = make(map[string]LocalUser, len(wrapper.Users))
	for _, user := range wrapper.Users {
		if user.Username == "" {
			continue
		}
		lu.users[user.Username] = user
	}

	return nil
}

// Authenticate verifies username and password
func (lu *LocalUsers) Authenticate(username, password string) (*LocalUser, error) {
	lu.mu.RLock()
	user, exists := lu.users[username]
	lu.mu.RUnlock()

	if !exists {
		lu.logger.Debug("User not found", "username", username)
		return nil, errors.New("invalid credentials")
	}

	if user.PasswordHash == "" {
		lu.logger.Debug("User has no password hash", "username", username)
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		lu.logger.Debug("Password verification failed", "username", username)
		return nil, errors.New("invalid credentials")
	}

	lu.logger.Info("Local authentication successful", "username", username)
	return &user, nil
}

// NewLocalProvider creates a new local authentication provider
func NewLocalProvider(config *LocalConfig, tokenManager TokenManager, logger *slog.Logger, authManagerParent *AuthManager) (*LocalProvider, error) {
	if logger == nil {
		logger = slog.Default()
	}

	logger = logger.With("component", "local-auth")

	var users *LocalUsers
	var err error

	if config.UsersPath != "" {
		users, err = LoadLocalUsers(config.UsersPath, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to load local users: %w", err)
		}
	}

	return &LocalProvider{
		ProviderBase:          NewProviderBase(tokenManager, logger, authManagerParent),
		config:                config,
		users:                 users,
		bootstrapLoginAllowed: config.BootstrapLoginAllowed,
		bootstrapUser:         config.BootstrapUser,
		bootstrapPasswd:       config.BootstrapPasswd,
	}, nil
}

// Name returns the provider name
func (lp *LocalProvider) Name() string {
	return LOCAL_PROVIDER
}

// StartAuth is not applicable for local auth (handled via direct login)
func (lp *LocalProvider) StartAuth(w http.ResponseWriter, r *http.Request, redirectAfter string) error {
	return errors.New("local authentication does not support redirect flow")
}

// HandleCallback is not applicable for local auth
func (lp *LocalProvider) HandleCallback(w http.ResponseWriter, r *http.Request) (*TokenClaims, error) {
	return nil, errors.New("local authentication does not support callback flow")
}

// Logout clears local session (no external logout needed)
func (lp *LocalProvider) Logout(w http.ResponseWriter, r *http.Request) error {
	lp.logger.Debug("Local logout completed")
	return nil
}

// ValidateToken validates a token (delegates to token manager)
func (lp *LocalProvider) ValidateToken(token string) (*TokenClaims, error) {
	return lp.tokenManager.ValidateToken(token)
}

// Authenticate performs username/password authentication
func (lp *LocalProvider) Authenticate(username, password string) (*TokenClaims, error) {
	var user *LocalUser
	var err error

	// Try file-based users first
	if lp.users != nil {
		user, err = lp.users.Authenticate(username, password)
		if err == nil {
			return lp.createTokenFromUser(user), nil
		}
		lp.logger.Debug("File-based authentication failed", "username", username, "error", err)
	}

	// Fallback to bootstrap user
	if lp.bootstrapLoginAllowed && lp.bootstrapUser != "" && lp.bootstrapPasswd != "" {
		if username == lp.bootstrapUser && lp.constantTimePasswordCompare(password, lp.bootstrapPasswd) {
			user = &LocalUser{
				Username: lp.bootstrapUser,
				Email:    "bootstrap@localhost",
				Roles:    []string{"admin"}, // Bootstrap user gets admin role
			}
			lp.logger.Info("Bootstrap authentication successful", "username", username)
			return lp.createTokenFromUser(user), nil
		}
	}

	lp.logger.Debug("Local authentication failed", "username", username)
	return nil, errors.New("invalid credentials")
}

// createTokenFromUser creates a token from a local user
func (lp *LocalProvider) createTokenFromUser(user *LocalUser) *TokenClaims {
	roles := user.Roles
	if len(roles) == 0 {
		roles = []string{"viewer"}
	}
	return &TokenClaims{
		Sub:       LOCAL_PROVIDER + ":" + user.Username,
		Username:  user.Username,
		Email:     user.Email,
		Roles:     roles,
		Provider:  LOCAL_PROVIDER,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: 0, // server owns TTL
	}
}

// constantTimePasswordCompare performs constant-time password comparison
func (lp *LocalProvider) constantTimePasswordCompare(provided, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
