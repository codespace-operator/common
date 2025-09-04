# rbac

Casbin-backed RBAC with **hot-reload** of model/policy files and handy HTTP helpers.

## What you get

- `RBACInterface` with `Enforce`, `EnforceAny`, `EnforceAsSubject`
- Introspection helpers: `GetUserPermissions`, `GetAllowedNamespaces`, `CanAccessNamespace`, `GetRolesForUser`
- File watcher that reloads on changes (great with Kubernetes ConfigMaps)
- HTTP helpers via `Middleware` (`MustCan`, `MustCanAny`, `K8sCan`)

## Install

```go
import "github.com/codespace-operator/common/auth/pkg/rbac"
```

## Configuration & defaults

You can pass explicit paths or use environment variables. Defaults are:

- Model path: `/etc/codespace-operator/rbac/model.conf`
- Policy path: `/etc/codespace-operator/rbac/policy.csv`
- Env overrides: `RBAC_MODEL_PATH`, `RBAC_POLICY_PATH`

```go
r, err := rbac.NewRBAC(ctx, rbac.RBACConfig{
  ModelPath:  os.Getenv("RBAC_MODEL_PATH"),
  PolicyPath: os.Getenv("RBAC_POLICY_PATH"),
  Logger:     slog.Default(),
})
if err != nil { panic(err) }
```

### Example model (very small)

```ini
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
```

### Example policy

```csv
# admin can do anything
p, admin,  *,           *,    *,  allow
# allow cluster-level list of namespaces
p, admin,  namespaces,  list, *,  allow
# editor CRUD on "session" resources
p, editor, session,     get,    *, allow
p, editor, session,     list,   *, allow
p, editor, session,     watch,  *, allow
p, editor, session,     create, *, allow
p, editor, session,     update, *, allow
p, editor, session,     delete, *, allow
p, editor, session,     scale,  *, allow
# viewer read-only
p, viewer, session,     get,  *,  allow
p, viewer, session,     list, *,  allow
p, viewer, session,     watch,*,  allow
```

## Using with `pkg/auth`

```go
authmw := auth.NewMiddleware(am, slog.Default())
rbacmw := rbac.NewMiddleware(r, slog.Default())

mux.Handle("/api/sessions",
  authmw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // domain = namespace, resource = "session", action = "create"
    if _, ok := rbacmw.MustCan(w, r, "session", "create", "team-a"); !ok { return }
    w.Write([]byte(` + "`" + `{"created":true}` + "`" + `))
  })),
)
```

- `MustCan` pulls `*auth.TokenClaims` from the request context (set by `RequireAuth`) and returns 403 if denied.
- Use `MustCanAny` when multiple actions are acceptable.

## Kubernetes permission checks (service account)

Use `K8sCan` to verify the server's own RBAC in the cluster via `SelfSubjectAccessReview`:

```go
ok := rbacmw.K8sCan(ctx, kubeClient, authv1.ResourceAttributes{
  Group:    "", Resource: "pods", Verb: "list", Namespace: "team-a",
})
if !ok { http.Error(w, "server missing k8s perms", 500); return }
```

## Hot reload behavior

- Both `model.conf` and `policy.csv` are watched **and** their parent directories.
- A simple debounce prevents thrashing (useful for K8s ConfigMap symlink swaps).
- Set `CASBIN_LOG_ENABLED=1` to emit casbin decision logs.

## Introspection helpers

```go
perms, _ := r.GetUserPermissions(sub, roles, []string{"team-a","team-b"}, []string{"create","list","delete"})
// perms.Namespaces["team-a"] -> []string of allowed actions

allowed, _ := r.GetAllowedNamespaces(sub, roles, []string{"dev","prod"}, "list")
hasAny, _ := r.CanAccessNamespace(sub, roles, "dev")
allRoles, _ := r.GetRolesForUser(sub)
```

## Testing

```bash
go test ./pkg/rbac -v
```
