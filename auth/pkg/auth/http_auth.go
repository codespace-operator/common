package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type AuthHTTP struct {
	m      Manager
	logger *slog.Logger
}

func NewAuthHTTP(m Manager, logger *slog.Logger) *AuthHTTP {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthHTTP{m: m, logger: logger.With("component", "auth-http")}
}

// OIDCCallback godoc
// @Summary      OIDC callback
// @Description  Handles OIDC provider callback, issues session, and redirects.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      302 {string} string "Redirect"
// @Failure      503 {string} string "OIDC provider unavailable"
// @Failure      401 {string} string "OIDC callback failed"
// @Failure      500 {string} string "Failed to issue session"
// @Router       /auth/oidc/callback [get]
func (h *AuthHTTP) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	prov := h.m.GetProvider(OIDC_PROVIDER)
	oidcProv, ok := prov.(*OIDCProvider)
	if !ok || oidcProv == nil {
		http.Error(w, "oidc provider unavailable", http.StatusServiceUnavailable)
		return
	}

	claims, err := oidcProv.HandleCallback(w, r)
	if err != nil {
		http.Error(w, "oidc callback failed", http.StatusUnauthorized)
		return
	}

	// Single place that issues the session token + cookie:
	if _, err := h.m.IssueSession(w, r, claims); err != nil {
		http.Error(w, "failed to issue session", http.StatusInternalServerError)
		return
	}

	// Resolve post-login redirect purely from the cookie:
	dest := "/"
	if pc, err := r.Cookie("post_auth_redirect"); err == nil && isSafeRedirect(pc.Value) {
		dest = pc.Value
		h.m.ClearCookie(w, "post_auth_redirect", CookieTempAuth)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// LocalLogin godoc
// @Summary      Local login
// @Description  Authenticates user with username and password, issues session.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      object{username=string,password=string} true "Login credentials"
// @Success      200   {object}  map[string]interface{} "Token and user info"
// @Success      204   {string}  string "No Content"
// @Failure      404   {string}  string "Local auth disabled"
// @Failure      400   {string}  string "Bad request"
// @Failure      401   {string}  string "Invalid credentials"
// @Failure      500   {string}  string "Failed to issue session"
// @Router       /auth/login [post]
func (h *AuthHTTP) LocalLogin(w http.ResponseWriter, r *http.Request) {
	lp := h.m.GetLocalProvider()
	if lp == nil {
		http.Error(w, "local auth disabled", http.StatusNotFound)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	claims, err := lp.Authenticate(body.Username, body.Password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := h.m.IssueSession(w, r, claims)
	if err != nil {
		http.Error(w, "failed to issue session", http.StatusInternalServerError)
		return
	}

	// If the client prefers JSON, return token payload for convenience
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": token,
			"user":  claims.Username,
			"roles": claims.Roles,
		})
		return
	}

	// Default: empty 204 + cookie already set
	w.WriteHeader(http.StatusNoContent)
}

// Refresh godoc
// @Summary      Refresh session
// @Description  Rotates session cookie if valid, enforces absolute session max.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      204 {string} string "No Content"
// @Failure      401 {string} string "Unauthorized"
// @Failure      500 {string} string "Failed to refresh session"
// @Router       /auth/refresh [post]
func (h *AuthHTTP) Refresh(w http.ResponseWriter, r *http.Request) {
	claims, err := h.m.ValidateRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Optional absolute session cap (type assert to reach config without changing interface)
	if am, ok := h.m.(*AuthManager); ok && am.config.AbsoluteSessionMax > 0 {
		age := time.Since(claims.IssuedTime())
		if age > am.config.AbsoluteSessionMax {
			// hard stop: client must fully re-auth with the provider
			h.m.ClearAuthCookie(w)
			http.Error(w, "session too old; please sign in again", http.StatusUnauthorized)
			return
		}
	}

	if _, err := h.m.IssueSession(w, r, claims); err != nil {
		http.Error(w, "failed to refresh session", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Logout godoc
// @Summary      Logout
// @Description  Clears session cookie and logs out from provider if available.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      204 {string} string "No Content"
// @Router       /auth/logout [post]
func (h *AuthHTTP) Logout(w http.ResponseWriter, r *http.Request) {
	h.m.ClearAuthCookie(w)
	if p := h.m.GetProvider(OIDC_PROVIDER); p != nil {
		// Provider may redirect (OIDC end-session)
		_ = p.Logout(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
