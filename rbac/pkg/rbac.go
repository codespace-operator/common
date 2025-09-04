package rbac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	cmodel "github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/fsnotify/fsnotify"
	authv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	auth "github.com/codespace-operator/common/auth/pkg/auth"
)

const (
	defaultModelPath  = "/etc/codespace-operator/rbac/model.conf"
	defaultPolicyPath = "/etc/codespace-operator/rbac/policy.csv"
	envModelPath      = "RBAC_MODEL_PATH"
	envPolicyPath     = "RBAC_POLICY_PATH"
)

// RBACInterface defines the contract for RBAC systems
// RBACInterface defines the contract for RBAC systems
type RBACInterface interface {
	// Core enforcement
	Enforce(subject string, roles []string, resource, action, domain string) (bool, error)
	EnforceAny(subjects []string, roles []string, resource, action, domain string) (bool, error)
	EnforceAsSubject(subject, resource, action, domain string) (bool, error)

	// Permission introspection
	// New, domain-centric helpers
	GetAllowedDomains(subject string, roles []string, resource string, domains []string, action string) ([]string, error)
	GetAllowedResources(subject string, roles []string, resources []string, action string, domain string) ([]string, error)

	// Optional summary (unchanged, but you can rename later if you want)
	GetUserPermissions(subject string, roles []string, resource string, domains []string, actions []string) (*UserPermissions, error)

	// Management
	GetRolesForUser(subject string) ([]string, error)
	Reload() error
}

// RBAC implements RBACInterface with Casbin
type RBAC struct {
	mu         sync.RWMutex
	enf        *casbin.Enforcer
	modelPath  string
	policyPath string
	logger     *slog.Logger
}

// RBACConfig holds configuration for RBAC initialization
type RBACConfig struct {
	ModelPath  string
	PolicyPath string
	Logger     *slog.Logger
}

// Middleware provides HTTP middleware functions
type Middleware struct {
	rbac   RBACInterface
	logger *slog.Logger
}

// PermissionCheck represents a single permission check result
type PermissionCheck struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Domain   string `json:"domain"`
	Allowed  bool   `json:"allowed"`
}

// UserPermissions represents all permissions for a user
// UserPermissions represents all permissions for a user
type UserPermissions struct {
	Subject     string            `json:"subject"`
	Roles       []string          `json:"roles"`
	Permissions []PermissionCheck `json:"permissions"`
	// Domains (previously Domains): domain -> allowed actions
	Domains map[string][]string `json:"domains"`
}

// NewMiddleware creates RBAC middleware
func NewMiddleware(rbac RBACInterface, logger *slog.Logger) *Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return &Middleware{rbac: rbac, logger: logger}
}

// MustCan checks authorization and writes 403 if denied
func (m *Middleware) MustCan(w http.ResponseWriter, r *http.Request, resource, action, domain string) (*auth.TokenClaims, bool) {
	cl := auth.FromContext(r)
	if cl == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}

	ok, err := m.rbac.Enforce(cl.Sub, cl.Roles, resource, action, domain)
	if err != nil {
		m.logger.Error("RBAC enforcement error",
			"error", err,
			"subject", cl.Sub,
			"resource", resource,
			"action", action,
			"domain", domain)
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}

	if !ok {
		m.logger.Debug("RBAC access denied",
			"subject", cl.Sub,
			"roles", cl.Roles,
			"resource", resource,
			"action", action,
			"domain", domain)
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}

	return cl, true
}

// CanAny checks if user has any of the specified permissions
func (m *Middleware) CanAny(cl *auth.TokenClaims, resource string, actions []string, domain string) bool {
	for _, action := range actions {
		if ok, err := m.rbac.Enforce(cl.Sub, cl.Roles, resource, action, domain); err == nil && ok {
			return true
		}
	}
	return false
}

// MustCanAny checks if user has any of the specified permissions, returns 403 if not
func (m *Middleware) MustCanAny(w http.ResponseWriter, r *http.Request, resource string, actions []string, domain string) (*auth.TokenClaims, bool) {
	cl := auth.FromContext(r)
	if cl == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}

	if !m.CanAny(cl, resource, actions, domain) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}

	return cl, true
}

// K8sCan checks if the server's service account can perform a Kubernetes operation
func (m *Middleware) K8sCan(ctx context.Context, c client.Client, ra authv1.ResourceAttributes) bool {
	ssar := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &ra,
		},
	}

	if err := c.Create(ctx, ssar); err != nil {
		m.logger.Error("Failed to check Kubernetes permissions",
			"error", err,
			"resource", ra.Resource,
			"verb", ra.Verb)
		return false
	}

	return ssar.Status.Allowed
}

// NewRBAC creates a new RBAC instance with proper logging and file watching
func NewRBAC(ctx context.Context, config RBACConfig) (RBACInterface, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Set defaults if paths not provided
	modelPath := config.ModelPath
	if modelPath == "" {
		if envPath := strings.TrimSpace(os.Getenv(envModelPath)); envPath != "" {
			modelPath = envPath
		} else {
			modelPath = defaultModelPath
		}
	}

	policyPath := config.PolicyPath
	if policyPath == "" {
		if envPath := strings.TrimSpace(os.Getenv(envPolicyPath)); envPath != "" {
			policyPath = envPath
		} else {
			policyPath = defaultPolicyPath
		}
	}

	r := &RBAC{
		modelPath:  modelPath,
		policyPath: policyPath,
		logger:     config.Logger.With("component", "rbac"),
	}

	if err := r.reload(); err != nil {
		return nil, fmt.Errorf("initial RBAC load failed: %w", err)
	}

	// Start file watcher
	if err := r.startWatcher(ctx); err != nil {
		r.logger.Warn("Failed to start RBAC file watcher", "error", err)
	}

	return r, nil
}

// startWatcher starts file system watching for hot reload
func (r *RBAC) startWatcher(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Watch both files and their parent directories (for ConfigMap-style updates)
	watchPaths := uniqueNonEmpty([]string{
		r.modelPath,
		r.policyPath,
		filepath.Dir(r.modelPath),
		filepath.Dir(r.policyPath),
	})

	for _, path := range watchPaths {
		if err := watcher.Add(path); err != nil {
			r.logger.Warn("Failed to watch path", "path", path, "error", err)
		}
	}

	go func() {
		defer watcher.Close()

		// Simple debounce to coalesce flurries of writes
		var lastReload time.Time
		const debounce = 250 * time.Millisecond

		for {
			select {
			case <-ctx.Done():
				r.logger.Debug("RBAC file watcher stopped")
				return
			case event := <-watcher.Events:
				if event.Op&(fsnotify.Create|fsnotify.Write) == 0 {
					continue
				}
				if _, err1 := os.Stat(r.modelPath); err1 != nil {
					continue
				}
				if _, err2 := os.Stat(r.policyPath); err2 != nil {
					continue
				}
				_ = r.reload()

				now := time.Now()
				if now.Sub(lastReload) < debounce {
					continue
				}
				lastReload = now

				if err := r.reload(); err != nil {
					r.logger.Error("RBAC reload failed after file system event", "error", err, "event", event.Name)
				} else {
					r.logger.Info("RBAC policies reloaded after file system event", "event", event.Name)
				}
			case err := <-watcher.Errors:
				if err != nil {
					r.logger.Warn("RBAC file watcher error", "error", err)
				}
			}
		}
	}()

	return nil
}

// reload rebuilds the Enforcer from the current files
func (r *RBAC) reload() error {
	// Load model
	model, err := cmodel.NewModelFromFile(r.modelPath)
	if err != nil {
		return fmt.Errorf("failed to load model from %s: %w", r.modelPath, err)
	}

	// Load policy via file adapter
	adapter := fileadapter.NewAdapter(r.policyPath)
	enforcer, err := casbin.NewEnforcer(model, adapter)
	if err != nil {
		return fmt.Errorf("failed to create enforcer: %w", err)
	}

	// Enable logging in debug builds
	if os.Getenv("CASBIN_LOG_ENABLED") == "1" {
		enforcer.EnableLog(true)
	}

	r.mu.Lock()
	r.enf = enforcer
	r.mu.Unlock()

	r.logger.Info("RBAC policies reloaded successfully")
	return nil
}

// Reload forces a reload of RBAC policies
func (r *RBAC) Reload() error {
	if _, err := os.Stat(r.modelPath); err != nil {
		return err
	}
	if _, err := os.Stat(r.policyPath); err != nil {
		return err
	}
	return r.reload()
}

// Enforce checks (subject, resource, action, domain) with support for user roles
func (r *RBAC) Enforce(subject string, roles []string, resource, action, domain string) (bool, error) {
	r.mu.RLock()
	enf := r.enf
	r.mu.RUnlock()

	if enf == nil {
		return false, errors.New("rbac not initialized")
	}

	// Debug logging
	if os.Getenv("CASBIN_LOG_ENABLED") == "1" {
		r.logger.Debug("RBAC enforce",
			"subject", subject,
			"roles", roles,
			"resource", resource,
			"action", action,
			"domain", domain)
	}

	// Try the concrete identity first
	ok, err := enf.Enforce(subject, resource, action, domain)
	if err != nil {
		return false, fmt.Errorf("enforcement failed for subject %s: %w", subject, err)
	}
	if ok {
		return true, nil
	}

	// Then try each role as a subject
	for _, role := range roles {
		if role == "" {
			continue
		}
		ok, err = enf.Enforce(role, resource, action, domain)
		if err != nil {
			return false, fmt.Errorf("enforcement failed for role %s: %w", role, err)
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

// EnforceAny checks alternative identities
func (r *RBAC) EnforceAny(subjects []string, roles []string, resource, action, domain string) (bool, error) {
	r.mu.RLock()
	enf := r.enf
	r.mu.RUnlock()

	if enf == nil {
		return false, errors.New("rbac not initialized")
	}

	// Try concrete subjects
	for _, subject := range uniqueNonEmpty(subjects) {
		if ok, err := enf.Enforce(subject, resource, action, domain); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}

	// Try roles as subjects
	for _, role := range uniqueNonEmpty(roles) {
		if ok, err := enf.Enforce(role, resource, action, domain); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}

	return false, nil
}

// EnforceAsSubject checks permissions for a specific subject
func (r *RBAC) EnforceAsSubject(subject, resource, action, domain string) (bool, error) {
	r.mu.RLock()
	enf := r.enf
	r.mu.RUnlock()

	if enf == nil {
		return false, errors.New("rbac not initialized")
	}

	return enf.Enforce(subject, resource, action, domain)
}

// GetUserPermissions returns comprehensive permission information
func (r *RBAC) GetUserPermissions(subject string, roles []string, resource string, domains []string, actions []string) (*UserPermissions, error) {
	r.mu.RLock()
	enf := r.enf
	r.mu.RUnlock()

	if enf == nil {
		return nil, errors.New("rbac not initialized")
	}

	if len(actions) == 0 {
		actions = []string{"get", "list", "watch", "create", "update", "delete", "scale"}
	}

	permissions := &UserPermissions{
		Subject:     subject,
		Roles:       roles,
		Permissions: make([]PermissionCheck, 0),
		Domains:     make(map[string][]string),
	}

	// Check each combination of resource, action, and domain
	for _, dom := range domains {
		allowedActions := make([]string, 0)

		for _, action := range actions {
			allowed, err := r.Enforce(subject, roles, resource, action, dom)
			if err != nil {
				return nil, fmt.Errorf("failed to check permission for %s/%s/%s: %w", subject, action, dom, err)
			}

			permissions.Permissions = append(permissions.Permissions, PermissionCheck{
				Resource: resource,
				Action:   action,
				Domain:   dom,
				Allowed:  allowed,
			})

			if allowed {
				allowedActions = append(allowedActions, action)
			}
		}

		if len(allowedActions) > 0 {
			permissions.Domains[dom] = allowedActions
		}
	}

	return permissions, nil
}

// GetAllowedDomains returns domains where the user can perform `action` on `resource`.
func (r *RBAC) GetAllowedDomains(subject string, roles []string, resource string, domains []string, action string) ([]string, error) {
	allowed := make([]string, 0, len(domains))
	for _, d := range domains {
		ok, err := r.Enforce(subject, roles, resource, action, d)
		if err != nil {
			return nil, fmt.Errorf("failed to check domain %s: %w", d, err)
		}
		if ok {
			allowed = append(allowed, d)
		}
	}
	return allowed, nil
}

// GetAllowedResources returns resources where the user can perform `action` in `domain`.
func (r *RBAC) GetAllowedResources(subject string, roles []string, resources []string, action string, domain string) ([]string, error) {
	allowed := make([]string, 0, len(resources))
	for _, res := range resources {
		ok, err := r.Enforce(subject, roles, res, action, domain)
		if err != nil {
			return nil, fmt.Errorf("failed to check resource %s: %w", res, err)
		}
		if ok {
			allowed = append(allowed, res)
		}
	}
	return allowed, nil
}

// CanAccessDomain checks if user has any resource permissions in a domain
func (r *RBAC) CanAccessDomain(subject string, roles []string, resource string, domain string) (bool, error) {
	actions := []string{"get", "list", "watch", "create", "update", "delete", "scale"}

	for _, action := range actions {
		ok, err := r.Enforce(subject, roles, resource, action, domain)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

// GetRolesForUser returns all roles (including inherited) for a user
func (r *RBAC) GetRolesForUser(subject string) ([]string, error) {
	r.mu.RLock()
	enf := r.enf
	r.mu.RUnlock()

	if enf == nil {
		return nil, errors.New("rbac not initialized")
	}

	return enf.GetImplicitRolesForUser(subject)
}

// uniqueNonEmpty removes duplicates and empty strings
func uniqueNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
