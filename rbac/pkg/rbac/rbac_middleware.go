package rbac

import (
	"context"
	"log/slog"
	"net/http"

	authv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Middleware provides HTTP middleware functions
type Middleware struct {
	rbac    RBACInterface
	extract PrincipalExtractor
	logger  *slog.Logger
}

// NewMiddleware creates RBAC middleware
func NewMiddleware(rbac RBACInterface, extract PrincipalExtractor, logger *slog.Logger) *Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return &Middleware{rbac: rbac, extract: extract, logger: logger}
}

// MustCan checks authorization and writes 403 if denied
func (m *Middleware) MustCan(w http.ResponseWriter, r *http.Request, resource, action, domain string) (*Principal, bool) {
	pr, err := m.extract(r)
	if err != nil || pr == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}

	ok, err := m.rbac.Enforce(pr.Subject, pr.Roles, resource, action, domain)
	if err != nil {
		m.logger.Error("RBAC enforcement error",
			"error", err,
			"subject", pr.Subject,
			"resource", resource,
			"action", action,
			"domain", domain)
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}

	if !ok {
		m.logger.Debug("RBAC access denied",
			"subject", pr.Subject,
			"roles", pr.Roles,
			"resource", resource,
			"action", action,
			"domain", domain)
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}

	return pr, true
}

// CanAny checks if user has any of the specified permissions
func (m *Middleware) CanAny(pr *Principal, resource string, actions []string, domain string) bool {
	for _, action := range actions {
		if ok, err := m.rbac.Enforce(pr.Subject, pr.Roles, resource, action, domain); err == nil && ok {
			return true
		}
	}
	return false
}

// MustCanAny checks if user has any of the specified permissions, returns 403 if not
func (m *Middleware) MustCanAny(w http.ResponseWriter, r *http.Request, resource string, actions []string, domain string) (*Principal, bool) {
	pr, err := m.extract(r)
	if err != nil || pr == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}

	if !m.CanAny(pr, resource, actions, domain) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}

	return pr, true
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
