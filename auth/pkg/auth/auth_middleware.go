package auth

import (
	"log/slog"
	"net/http"
	"strings"
)

// Middleware provides HTTP middleware functions
type Middleware struct {
	authManager Manager //
	logger      *slog.Logger
}

// NewMiddleware creates authentication middleware
func NewMiddleware(am Manager, logger *slog.Logger) *Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return &Middleware{authManager: am, logger: logger}
}

// RequireAuth middleware that requires valid authentication
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := m.authManager.ValidateRequest(r)
		if err != nil {
			m.logger.Debug("Authentication failed", "error", err, "path", r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		r = r.WithContext(WithClaims(r.Context(), claims))
		next.ServeHTTP(w, r)
	})
}

// OptionalAuth middleware that adds user info if available but doesn't require it
func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims, err := m.authManager.ValidateRequest(r); err == nil {
			r = r.WithContext(WithClaims(r.Context(), claims))
		}
		next.ServeHTTP(w, r)
	})
}

// AuthGate provides smart authentication routing
func (m *Middleware) AuthGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Public endpoints (no auth required)
		if m.isPublicPath(path) {
			next.ServeHTTP(w, r)
			return
		}

		// API endpoints require authentication
		if strings.HasPrefix(path, "/api/") {
			m.RequireAuth(next).ServeHTTP(w, r)
			return
		}

		// Default to serving content with optional auth
		m.OptionalAuth(next).ServeHTTP(w, r)
	})
}

// isPublicPath checks if a path is publicly accessible
func (m *Middleware) isPublicPath(path string) bool {
	publicPaths := []string{
		"/healthz",
		"/readyz",
		"/",
	}

	publicPrefixes := []string{
		m.authManager.GetAuthPath(),
		m.authManager.GetAuthLogoutPath(),
		"/assets/",
		"/static/",
	}

	// Check exact matches
	for _, publicPath := range publicPaths {
		if path == publicPath {
			return true
		}
	}

	// Check prefixes
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}
