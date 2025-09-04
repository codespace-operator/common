package rbac

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// helpers
func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

const modelStr = `
[request_definition]
r = sub, obj, act, dom

[policy_definition]
p = sub, obj, act, dom, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p_eft == allow)) && !some(where (p_eft == deny))

[matchers]
m = (g(r.sub, p.sub) || r.sub == p.sub) && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*") && (p.dom == "*" || r.dom == p.dom)
`

const policyStr = `
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

func newRBAC(t *testing.T) RBACInterface {
	t.Helper()
	dir := t.TempDir()
	m := filepath.Join(dir, "model.conf")
	p := filepath.Join(dir, "policy.csv")
	write(t, m, modelStr)
	write(t, p, policyStr)

	r, err := NewRBAC(context.Background(), RBACConfig{
		ModelPath:  m,
		PolicyPath: p,
		Logger:     nil, // defaults to slog.Default()
	})
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	return r
}

func TestRBAC_Enforce_RolesAndSubjects(t *testing.T) {
	r := newRBAC(t)

	tests := []struct {
		name      string
		subject   string
		roles     []string
		obj, act  string
		dom       string
		wantAllow bool
	}{
		{"admin_anything", "someone", []string{"admin"}, "session", "delete", "prod", true},
		{"viewer_read_only", "user", []string{"viewer"}, "session", "get", "ns1", true},
		{"viewer_cannot_write", "user", []string{"viewer"}, "session", "create", "ns1", false},
		{"editor_crud", "user", []string{"editor"}, "session", "update", "team-a", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := r.Enforce(tc.subject, tc.roles, tc.obj, tc.act, tc.dom)
			if err != nil {
				t.Fatalf("Enforce error: %v", err)
			}
			if ok != tc.wantAllow {
				t.Fatalf("want %v, got %v", tc.wantAllow, ok)
			}
		})
	}
}

func TestRBAC_Reload_NoSleep(t *testing.T) {
	// Show deterministic reload without relying on fsnotify timing:
	// write a new policy and call Reload directly.
	dir := t.TempDir()
	m := filepath.Join(dir, "model.conf")
	p := filepath.Join(dir, "policy.csv")
	write(t, m, modelStr)
	write(t, p, policyStr)

	r0, err := NewRBAC(context.Background(), RBACConfig{
		ModelPath:  m,
		PolicyPath: p,
	})
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	// viewer cannot create initially
	ok, _ := r0.Enforce("viewer", nil, "session", "create", "ns1")
	if ok {
		t.Fatal("viewer create should be denied initially")
	}

	// append allow rule and force Reload()
	appendLine := "\np, viewer, session, create, *, allow\n"
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open policy: %v", err)
	}
	if _, err := f.WriteString(appendLine); err != nil {
		t.Fatalf("append policy: %v", err)
	}
	_ = f.Close()

	if err := r0.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	ok, _ = r0.Enforce("viewer", nil, "session", "create", "ns1")
	if !ok {
		t.Fatal("viewer create should be allowed after reload")
	}
}

func TestRBAC_GetAllowedDomains(t *testing.T) {
	r := newRBAC(t)

	domains := []string{"team-a", "team-b", "prod"}
	got, err := r.GetAllowedDomains("user", []string{"viewer"}, "session", domains, "get")
	if err != nil {
		t.Fatalf("GetAllowedDomains: %v", err)
	}
	// viewer can read session in any domain per test policy
	if len(got) != len(domains) {
		t.Fatalf("expected all domains allowed for viewer get, got %v", got)
	}
}

func TestRBAC_GetAllowedResources(t *testing.T) {
	r := newRBAC(t)

	resources := []string{"session", "namespaces"} // policy grants list on namespaces only to admin
	got, err := r.GetAllowedResources("user", []string{"viewer"}, resources, "list", "any")
	if err != nil {
		t.Fatalf("GetAllowedResources: %v", err)
	}
	for _, res := range got {
		if res == "namespaces" {
			t.Fatalf("viewer should not be allowed to list namespaces, got %v", got)
		}
	}
}

func TestRBAC_SummaryUsesDomains(t *testing.T) {
	r := newRBAC(t)
	perms, err := r.GetUserPermissions("user", []string{"editor"}, "session", []string{"team-a", "team-b"}, []string{"create", "delete"})
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}
	if len(perms.Domains) == 0 {
		t.Fatalf("expected domain map to be populated")
	}
	if _, ok := perms.Domains["team-a"]; !ok {
		t.Fatalf("expected team-a key in domain map")
	}
}

func TestRBAC_EnforceAny(t *testing.T) {
	r := newRBAC(t)
	ok, err := r.EnforceAny([]string{"u1", "u2"}, []string{"viewer"}, "session", "list", "ns")
	if err != nil {
		t.Fatalf("EnforceAny: %v", err)
	}
	if !ok {
		t.Fatal("viewer should be allowed to list via role")
	}
}

// tiny sanity that watcher goroutine doesn't block test shutdown
func TestRBAC_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	m := filepath.Join(dir, "model.conf")
	p := filepath.Join(dir, "policy.csv")
	write(t, m, modelStr)
	write(t, p, policyStr)

	r, err := NewRBAC(ctx, RBACConfig{ModelPath: m, PolicyPath: p})
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}
	// cancel and do a quick call; should still work with last loaded state
	cancel()
	time.Sleep(10 * time.Millisecond) // tiny yield; not required but keeps races quiet
	ok, _ := r.Enforce("viewer", nil, "session", "get", "ns")
	if !ok {
		t.Fatal("viewer get should be allowed")
	}
}
