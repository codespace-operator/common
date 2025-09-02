package rbac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/codespace-operator/common/pkg/auth"
)

func NewRBACFromEnv(ctx context.Context) (*RBAC, error) {
	logger := &mockLogger{}
	modelPath := strings.TrimSpace(os.Getenv(envModelPath))
	if modelPath == "" {
		modelPath = defaultModelPath
	}
	policyPath := strings.TrimSpace(os.Getenv(envPolicyPath))
	if policyPath == "" {
		policyPath = defaultPolicyPath
	}

	r := &RBAC{modelPath: modelPath, policyPath: policyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}

	// Watch both files + their parent dir (K8s ConfigMap mounts replace symlinks)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	watchPaths := uniqueNonEmpty([]string{
		modelPath,
		policyPath,
		filepath.Dir(modelPath),
		filepath.Dir(policyPath),
	})

	for _, p := range watchPaths {
		_ = watcher.Add(p) // best-effort
	}

	go func() {
		defer watcher.Close()

		// Simple debounce to coalesce flurries of writes from kubelet
		var last time.Time
		const debounce = 250 * time.Millisecond

		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-watcher.Events:
				// React to any change on either file path or their dirs
				if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) == 0 {
					continue
				}
				now := time.Now()
				if now.Sub(last) < debounce {
					continue
				}
				last = now
				if err := r.reload(); err != nil && logger != nil {
					logger.Info("rbac reload failed: %v", err)
				} else if logger != nil {
					logger.Info("rbac reloaded after fsnotify: %s", ev.Name)
				}
			case err := <-watcher.Errors:
				if logger != nil && err != nil {
					logger.Info("rbac watcher error: %v", err)
				}
			}
		}
	}()

	return r, nil
}

// Example: shows how to use the RBAC system in HTTP handlers
/*
func demonstrateAPIUsage() {
		Example HTTP handler usage:

		func (h *handlers) handleCreateSession(deps *serverDeps) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				// Extract session creation request
				var req SessionCreateRequest
				json.NewDecoder(r.Body).Decode(&req)

				// RBAC check - user must have 'create' permission in target namespace
				cl, ok := mustCan(deps, w, r, "session", "create", req.Namespace)
				if !ok {
					return // Error already written by mustCan
				}

				// Proceed with session creation
				session := createSession(req, cl.Sub)
				writeJSON(w, session)
			}
		}

		// For operations requiring multiple permissions:
		func (h *handlers) handleBulkDelete(deps *serverDeps) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				var req BulkDeleteRequest
				json.NewDecoder(r.Body).Decode(&req)

				// Check permissions for each namespace
				for _, ns := range req.Namespaces {
					if _, ok := mustCan(deps, w, r, "session", "delete", ns); !ok {
						return
					}
				}

				// Proceed with bulk deletion
				result := performBulkDelete(req)
				writeJSON(w, result)
			}
		}
}
*/

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

const testModel = `
[request_definition]
r = sub, obj, act, dom

[policy_definition]
p = sub, obj, act, dom, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (g(r.sub, p.sub) || r.sub == p.sub) &&
    (r.obj == p.obj) &&
    (r.act == p.act || p.act == "*") &&
    (p.dom == "*" || r.dom == p.dom)
`

const testPolicy = `
p, admin,  *,           *,    *,  allow
p, admin,  namespaces,  list, *,  allow
p, editor, session,     get,  *,  allow
p, editor, session,     list, *,  allow
p, editor, session,     watch,*,  allow
p, editor, session,     create,*, allow
p, editor, session,     update,*, allow
p, editor, session,     delete,*, allow
p, editor, session,     scale, *, allow
p, viewer, session,     get,  *,  allow
p, viewer, session,     list, *,  allow
p, viewer, session,     watch,*,  allow
`

func newRBACForTest(t *testing.T, dir string) *RBAC {
	t.Helper()
	m := filepath.Join(dir, "model.conf")
	p := filepath.Join(dir, "policy.csv")
	write(t, m, testModel)
	write(t, p, testPolicy)
	t.Setenv(envModelPath, m)
	t.Setenv(envPolicyPath, p)
	r, err := NewRBACFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewRBACFromEnv: %v", err)
	}
	return r
}

func TestPolicyBasics(t *testing.T) {
	dir := t.TempDir()
	r := newRBACForTest(t, dir)

	// Admin: anything anywhere
	ok, _ := r.Enforce("admin", nil, "session", "delete", "team-a")
	if !ok {
		t.Fatal("admin should be allowed")
	}

	ok, _ = r.Enforce("developer", nil, "session", "create", "dev-frontend")
	if !ok {
		t.Fatal("dev-* should match dev-frontend")
	}

	// Viewer: read-only
	ok, _ = r.Enforce("viewer", nil, "session", "get", "team-a")
	if !ok {
		t.Fatal("viewer get should be allowed")
	}
	ok, _ = r.Enforce("viewer", nil, "session", "create", "team-a")
	if ok {
		t.Fatal("viewer create should be denied")
	}

	// Role carried in JWT roles array
	ok, _ = r.Enforce("alice", []string{"viewer"}, "session", "list", "team-b")
	if !ok {
		t.Fatal("alice with viewer role should be allowed to list")
	}
}

func TestClusterNamespacesListRequiresClusterRole(t *testing.T) {
	dir := t.TempDir()
	r := newRBACForTest(t, dir)

	// viewer cannot list namespaces (cluster-level)
	ok, _ := r.Enforce("viewer", nil, "namespaces", "list", "*")
	if ok {
		t.Fatal("viewer should not be allowed to list namespaces")
	}

	// admin can
	ok, _ = r.Enforce("admin", nil, "namespaces", "list", "*")
	if !ok {
		t.Fatal("admin should be allowed to list namespaces")
	}
}

func TestHotReload(t *testing.T) {
	dir := t.TempDir()
	r := newRBACForTest(t, dir)

	// Initially denied
	ok, _ := r.Enforce("viewer", nil, "session", "create", "ns1")
	if ok {
		t.Fatal("viewer create should be denied before update")
	}

	// Update policy to allow viewer create
	p := filepath.Join(dir, "policy.csv")
	appendLine := "p, viewer, session, create, *, allow\n"
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open policy: %v", err)
	}
	if _, err := f.WriteString(appendLine); err != nil {
		t.Fatalf("append policy: %v", err)
	}
	_ = f.Close()

	// Give the watcher a moment to detect & reload
	time.Sleep(500 * time.Millisecond)

	ok, _ = r.Enforce("viewer", nil, "session", "create", "ns1")
	if !ok {
		t.Fatal("viewer create should be allowed after policy update")
	}
}

// ExampleRBACUsage demonstrates how to use the enhanced RBAC system
func ExampleRBACUsage() {
	// This example shows how the RBAC system works in practice

	// 1. User Authentication (handled by auth handlers)
	user := &auth.TokenClaims{
		Username: "alice",
		Sub:      "abcd123-efgh5678",
		Email:    "alice@company.com",
		Roles:    []string{"codespace-editor"},
		Provider: auth.OIDC_PROVIDER,
	}

	// 2. RBAC Enforcement Examples
	rbac, _ := NewRBACFromEnv(context.Background())

	// Check if user can create sessions in team-alpha namespace
	canCreate, _ := rbac.Enforce(user.Sub, user.Roles, "session", "create", "team-alpha")
	fmt.Printf("Alice can create in team-alpha: %v\n", canCreate)

	// Check if user can delete sessions everywhere (should be false for non-admin)
	canDeleteAll, _ := rbac.Enforce(user.Sub, user.Roles, "session", "delete", "*")
	fmt.Printf("Alice can delete everywhere: %v\n", canDeleteAll)

	// Get comprehensive permissions for user
	permissions, _ := rbac.GetUserPermissions(user.Sub, user.Roles,
		[]string{"team-alpha", "team-beta", "prod-env"},
		[]string{"create", "delete", "list"})
	fmt.Printf("Alice's permissions: %+v\n", permissions)
}

// TestRBACScenarios tests common RBAC scenarios
func TestRBACScenarios(t *testing.T) {
	// Setup test RBAC
	dir := t.TempDir()
	rbac := newRBACForTest(t, dir)

	testCases := []struct {
		name        string
		subject     string
		roles       []string
		resource    string
		action      string
		namespace   string
		expected    bool
		description string
	}{
		// Admin scenarios
		{
			name:    "admin_can_do_anything",
			subject: "admin-user", roles: []string{"admin"},
			resource: "session", action: "delete", namespace: "production",
			expected:    true,
			description: "Admins should have full access to all namespaces",
		},
		{
			name:    "admin_can_list_namespaces",
			subject: "admin-user", roles: []string{"admin"},
			resource: "namespaces", action: "list", namespace: "*",
			expected:    true,
			description: "Admins should be able to list namespaces cluster-wide",
		},

		// Editor scenarios
		{
			name:    "editor_can_crud_sessions",
			subject: "editor-user", roles: []string{"editor"},
			resource: "session", action: "create", namespace: "dev-team-a",
			expected:    true,
			description: "Editors should be able to CRUD sessions in allowed namespaces",
		},
		{
			name:    "editor_cannot_delete_in_prod",
			subject: "editor-user", roles: []string{"editor"},
			resource: "session", action: "delete", namespace: "prod-env",
			expected:    false, // Based on deny policy in our example
			description: "Editors should be denied delete in production namespaces",
		},

		// Viewer scenarios
		{
			name:    "viewer_can_read_sessions",
			subject: "viewer-user", roles: []string{"viewer"},
			resource: "session", action: "get", namespace: "any-namespace",
			expected:    true,
			description: "Viewers should have read access to sessions",
		},
		{
			name:    "viewer_cannot_create_sessions",
			subject: "viewer-user", roles: []string{"viewer"},
			resource: "session", action: "create", namespace: "any-namespace",
			expected:    false,
			description: "Viewers should not be able to create sessions",
		},

		// Namespace-specific scenarios
		{
			name:    "user_specific_namespace_access",
			subject: "alice@company.com", roles: []string{},
			resource: "session", action: "create", namespace: "team-alpha",
			expected:    true, // Based on specific user policy
			description: "Users should have access to their assigned namespaces",
		},
		{
			name:    "user_no_access_other_namespace",
			subject: "alice@company.com", roles: []string{},
			resource: "session", action: "create", namespace: "team-beta",
			expected:    false,
			description: "Users should not have access to unassigned namespaces",
		},

		// Pattern matching scenarios
		{
			name:    "dev_pattern_matching",
			subject: "developer", roles: []string{"developer"},
			resource: "session", action: "create", namespace: "dev-frontend",
			expected:    true, // Matches dev-* pattern
			description: "Pattern matching should work for namespace prefixes",
		},
		{
			name:    "prod_pattern_deny",
			subject: "developer", roles: []string{"developer"},
			resource: "session", action: "create", namespace: "prod-frontend",
			expected:    false, // Should not match dev-* pattern
			description: "Pattern matching should restrict access appropriately",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rbac.Enforce(tc.subject, tc.roles, tc.resource, tc.action, tc.namespace)
			if err != nil {
				t.Fatalf("RBAC enforcement failed: %v", err)
			}

			if result != tc.expected {
				t.Errorf("%s: expected %v, got %v", tc.description, tc.expected, result)
			}
		})
	}
}

// Policy configuration examples and best practices
const policyExamples = `
# RBAC Policy Configuration Examples

## 1. Role Hierarchy
# Create a hierarchy where admin inherits editor, editor inherits viewer
g, admin, editor
g, editor, viewer

## 2. Namespace-Specific Access
# Grant team leads full access to their team namespaces
p, team-lead, session, *, team-*, allow
p, alice@company.com, session, *, team-alpha, allow
p, bob@company.com, session, *, team-beta, allow

## 3. Environment-Specific Restrictions
# Allow developers in dev environments, but restrict production
p, developer, session, (get|list|watch|create|update), dev-*, allow
p, developer, session, *, prod-*, deny

## 4. Action-Specific Permissions
# Give analysts read-only access across all namespaces
p, analyst, session, (get|list|watch), *, allow

## 5. Time-Based or Conditional Access (advanced)
# These would require custom matchers in the Casbin model
p, on-call-engineer, session, *, prod-*, allow  # During on-call hours
p, emergency-response, session, *, *, allow     # During incidents

## 6. Group-Based Access
# Map OIDC groups to internal roles
g, /ops-team, admin
g, /dev-team, editor
g, /qa-team, viewer

## 7. Resource-Specific Deny Policies
# Prevent deletion of sessions with specific labels
p, *, session, delete, *, deny  # Would need custom logic to check labels

## Best Practices:
# 1. Use explicit deny policies sparingly - they override allows
# 2. Prefer role-based policies over user-specific ones for maintainability
# 3. Use pattern matching (*) carefully - it can grant unintended access
# 4. Test policies thoroughly with the scenarios above
# 5. Use namespace patterns (dev-*, prod-*) for environment segregation
# 6. Document your policies and their intended use cases
`

// Configuration examples for different deployment scenarios
const configExamples = `
# Deployment Configuration Examples

## Single Tenant (Development)
# All authenticated users get admin access
g, authenticated-user, admin
p, admin, *, *, *, allow

## Multi-Tenant (Production)
# Strict role separation with namespace isolation
g, cluster-admin, admin
g, namespace-admin, editor
g, namespace-user, viewer

# Namespace-specific access
p, admin, *, *, *, allow
p, editor, session, *, {{.UserNamespace}}, allow
p, viewer, session, (get|list|watch), {{.UserNamespace}}, allow

## Enterprise (Complex Organization)
# Department-based access with cross-cutting roles
g, /dept-engineering/ops, admin
g, /dept-engineering/senior-dev, editor
g, /dept-engineering/dev, developer
g, /dept-qa, qa-engineer
g, /security-team, security-auditor

# Project-based namespaces
p, developer, session, *, proj-{{.ProjectName}}-*, allow
p, qa-engineer, session, (get|list|watch), *, allow
p, security-auditor, session, get, *, allow

## Regulatory Compliance (SOX/HIPAA)
# Segregation of duties and audit requirements
p, admin, *, *, non-prod-*, allow
p, prod-admin, *, *, prod-*, allow  # Separate role for production
p, auditor, *, get, *, allow       # Read-only access for auditors

# Deny policies for compliance
p, developer, session, (delete|update), prod-*, deny
p, *, session, *, audit-*, deny      # Special audit namespace
`

// Mock logger for testing
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, args ...any) {}
func (m *mockLogger) Info(msg string, args ...any)  {}
func (m *mockLogger) Warn(msg string, args ...any)  {}
func (m *mockLogger) Error(msg string, args ...any) {}
func (m *mockLogger) With(args ...any) *mockLogger  { return m }
