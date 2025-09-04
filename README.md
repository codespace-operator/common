# Codespace Common Modules

This repo contains reusable building blocks used within several applications.

- `pkg/auth`: pluggable authentication (OIDC + local), cookie/session helpers, middleware
- `pkg/rbac`: Casbin-backed authorization with hot-reload policies & HTTP helpers

## Quick links

- [pkg/auth/README.md](pkg/auth/README.md) – configure OIDC or local login, mint/validate sessions
- [pkg/rbac/README.md](pkg/rbac/README.md) – load model/policy, enforce permissions, middleware

## Minimal example (auth + rbac together)

```go
package main

import (
    "context"
    "log/slog"
    "net/http"
    "os"
    "time"

    "github.com/codespace-operator/common/auth/pkg/auth"
    "github.com/codespace-operator/common/auth/pkg/rbac"
)

func main() {
    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

    // --- Auth -----------------------------------------------------------------
    am, err := auth.NewAuthManager(&auth.AuthConfig{
        JWTSecret:         os.Getenv("JWT_SECRET"),           // required
        SessionCookieName: "codespace_session",               // optional
        SessionTTL:        8 * time.Hour,                     // optional
        AllowTokenParam:   false,                             // discourage
        OIDC: &auth.OIDCConfig{
            IssuerURL:    os.Getenv("OIDC_ISSUER"),
            ClientID:     os.Getenv("OIDC_CLIENT_ID"),
            ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
            RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),     // e.g. https://app.example.com/auth/sso/callback
            Scopes:       []string{"openid","profile","email"},
            // InsecureSkipVerify: true, // DEV ONLY
        },
        Local: &auth.LocalConfig{
            Enabled:               true,       // handy for dev/bootstrap
            UsersPath:             "",         // optional YAML/JSON file (see pkg/auth/README)
            BootstrapLoginAllowed: true,
            BootstrapUser:         "admin",
            BootstrapPasswd:       "admin",
        },
    }, logger)
    if err != nil { panic(err) }

    authmw := auth.NewMiddleware(am, logger)

    // --- RBAC -----------------------------------------------------------------
    r, err := rbac.NewRBAC(context.Background(), rbac.RBACConfig{
        // Can also be provided via env RBAC_MODEL_PATH / RBAC_POLICY_PATH
        ModelPath:  "", // defaults to /etc/codespace-operator/rbac/model.conf
        PolicyPath: "", // defaults to /etc/codespace-operator/rbac/policy.csv
        Logger:     logger,
    })
    if err != nil { panic(err) }
    rbacmw := rbac.NewMiddleware(r, logger)

    // --- HTTP wiring ----------------------------------------------------------
    mux := http.NewServeMux()

    // Auth endpoints (very thin examples)
    mux.HandleFunc("/auth/oidc/start", func(w http.ResponseWriter, r *http.Request) {
        am.GetProvider(auth.OIDC_PROVIDER).StartAuth(w, r, "/")
    })
    mux.HandleFunc("/auth/sso/callback", func(w http.ResponseWriter, r *http.Request) {
        claims, err := am.GetProvider(auth.OIDC_PROVIDER).HandleCallback(w, r)
        if err != nil { http.Error(w, err.Error(), 400); return }
        // issue app session cookie
        if _, err := am.IssueSession(w, r, claims); err != nil { http.Error(w, err.Error(), 500); return }
        http.Redirect(w, r, "/", http.StatusFound)
    })
    mux.HandleFunc("/auth/local/login", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "POST only", 405); return }
        lp := am.GetLocalProvider()
        if lp == nil { http.Error(w, "local disabled", 400); return }
        user := r.FormValue("username")
        pass := r.FormValue("password")
        claims, err := lp.Authenticate(user, pass)
        if err != nil { http.Error(w, "invalid creds", 401); return }
        am.IssueSession(w, r, claims)
        w.WriteHeader(204)
    })
    mux.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
        am.ClearAuthCookie(w)
        // best effort provider logout
        if p := am.GetProvider(auth.OIDC_PROVIDER); p != nil { _ = p.Logout(w, r) }
    })

    // Protected API: user must be authenticated AND authorized to create a session in "team-a"
    mux.Handle("/api/sessions", authmw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if _, ok := rbacmw.MustCan(w, r, "session", "create", "team-a"); !ok { return }
        w.Write([]byte(`{"ok":true}`))
    })))

    // Optional auth for UI/static
    root := authmw.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("hello"))
    }))
    mux.Handle("/", root)

    addr := ":8080"
    logger.Info("listening", "addr", addr)
    _ = http.ListenAndServe(addr, mux)
}
```
