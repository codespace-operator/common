# auth

Authentication utilities with pluggable **OIDC** and **Local** providers, a simple **JWT** session manager, and HTTP middleware.

## What you get

- `AuthManager` to initialize providers and mint/validate session cookies
- `OIDCProvider` with PKCE, nonce, state + optional Keycloak logout
- `LocalProvider` for bootstrap/dev login (YAML/JSON user store or a single bootstrap user)
- `Middleware` helpers: `RequireAuth`, `OptionalAuth`, `AuthGate`
- Small helpers for CORS, cookies, and extracting tokens

## Install

```go
import "github.com/codespace-operator/common/auth/pkg/auth"
```

## Configuration

```go
cfg := &auth.AuthConfig{
  JWTSecret:         "<random-32b>", // required; used to sign session JWT
  SessionCookieName: "codespace_session",
  SessionTTL:        8 * time.Hour,
  AllowTokenParam:   false,          // allow ?access_token=... (discouraged)

  OIDC: &auth.OIDCConfig{
    IssuerURL:    "https://keycloak.example.com/realms/myrealm",
    ClientID:     "my-client",
    ClientSecret: "xxxx",
    RedirectURL:  "https://app.example.com/auth/sso/callback",
    Scopes:       []string{"openid","profile","email"},
    // InsecureSkipVerify: true, // DEV ONLY
  },

  Local: &auth.LocalConfig{
    Enabled:               true,
    UsersPath:             "users.yaml", // YAML/JSON: see format below
    BootstrapLoginAllowed: true,
    BootstrapUser:         "admin",
    BootstrapPasswd:       "admin",
  },
}
am, _ := auth.NewAuthManager(cfg, slog.Default())
```

### Local users file format

YAML (preferred) or JSON:

```yaml
users:
  - username: alice
    email: alice@example.com
    # bcrypt hash (e.g. bcrypt of "alice")
    passwordHash: $2a$10$1C9s3Q5u8hHqD...
    roles: [editor]
  - username: bob
    email: bob@example.com
    passwordHash: $2a$10$....
    roles: [viewer]
```

> Generate bcrypt quickly:  
> `htpasswd -nbBC 10 "" "<password>" | sed -e 's/^.*:\$2y/\$2a/' -e 's/\$//;1q'`

## Typical endpoints

```go
// Start OIDC redirect
mux.HandleFunc("/auth/oidc/start", func(w http.ResponseWriter, r *http.Request) {
  am.GetProvider(auth.OIDC_PROVIDER).StartAuth(w, r, "/")
})

// OIDC callback → verify → issue session cookie
mux.HandleFunc("/auth/sso/callback", func(w http.ResponseWriter, r *http.Request) {
  claims, err := am.GetProvider(auth.OIDC_PROVIDER).HandleCallback(w, r)
  if err != nil { http.Error(w, err.Error(), 400); return }
  if _, err := am.IssueSession(w, r, claims); err != nil { http.Error(w, err.Error(), 500); return }
  http.Redirect(w, r, "/", http.StatusFound)
})

// Local login (POST form/json with username/password)
mux.HandleFunc("/auth/local/login", func(w http.ResponseWriter, r *http.Request) {
  lp := am.GetLocalProvider()
  if lp == nil { http.Error(w, "local disabled", 400); return }
  user := r.FormValue("username")
  pass := r.FormValue("password")
  claims, err := lp.Authenticate(user, pass)
  if err != nil { http.Error(w, "invalid creds", 401); return }
  am.IssueSession(w, r, claims)
  w.WriteHeader(204)
})

// Logout
mux.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
  am.ClearAuthCookie(w)
  if p := am.GetProvider(auth.OIDC_PROVIDER); p != nil {
    _ = p.Logout(w, r) // best effort redirect to end_session if configured
  }
})
```

## Middleware

```go
authmw := auth.NewMiddleware(am, slog.Default())

// hard requirement
mux.Handle("/api/private", authmw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  cl := auth.FromContext(r) // *auth.TokenClaims
  w.Write([]byte("hi " + cl.Username))
})))

// optional (claims present if user is logged in)
mux.Handle("/", authmw.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if cl := auth.FromContext(r); cl != nil { /* personalize UI */ }
  w.Write([]byte("welcome"))
})))
```

## Token & claims

- Session cookie stores a short HS256 JWT (not an OIDC token).
- `TokenClaims` fields: `Sub`, `Roles`, `Email`, `Username`, `Provider`, `IssuedAt`, `ExpiresAt`.
- OIDC roles will be taken from `roles` claim; if absent, `groups` is used.

## Security notes

- Cookies are `HttpOnly` and `SameSite=Lax`. `Secure` is derived from TLS/`X-Forwarded-Proto`.
- Keep `JWTSecret` long & random; rotate by re-deploying with a new secret (will invalidate sessions).

## Testing

```bash
go test ./pkg/auth -v
```
