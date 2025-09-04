package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// generateRandomString creates a cryptographically secure random string
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to less secure method if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// generatePKCEPair creates a PKCE code verifier and challenge
func generatePKCEPair() (verifier, challenge string) {
	verifier = generateRandomString(32)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return
}

// issuerIDFromURL creates a stable identifier from issuer URL
func issuerIDFromURL(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return hashString(issuer)
	}

	// Create stable ID from host and path
	id := strings.ToLower(strings.TrimSuffix(u.Host+u.Path, "/"))
	id = strings.ReplaceAll(id, "/", "~") // keycloak.example.com~realms~prod
	id = strings.ReplaceAll(id, ":", "-") // avoid delimiter collision

	if id == "" {
		return hashString(issuer)
	}
	return id
}

// hashString creates a short hash of a string
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash[:])[:16]
}

// isSafeRedirect checks if a redirect URL is safe (relative and not protocol-relative)
func isSafeRedirect(url string) bool {
	return url != "" && strings.HasPrefix(url, "/") && !strings.HasPrefix(url, "//")
}

// constantTimeEqual performs constant-time string comparison
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Cookie helper functions
func setTempCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})
}

func clearTempCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ExtractTokenFromRequest extracts JWT token from HTTP request
func ExtractTokenFromRequest(r *http.Request, cookieName string, allowURLParam bool) string {
	// 1. Try session cookie first
	if cookieName == "" {
		cookieName = "you_should_change_me"
	}

	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		return c.Value
	}

	// 2. Try Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) > 7 && strings.ToLower(auth[:7]) == "bearer " {
			return strings.TrimSpace(auth[7:])
		}
	}

	// 3. Try query parameter if enabled (not recommended)
	if allowURLParam {
		if token := r.URL.Query().Get("access_token"); token != "" {
			return token
		}
	}

	return ""
}

// sign creates HMAC signature for the message
func (j *JWTManager) sign(message string) []byte {
	mac := hmac.New(sha256.New, j.secret)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// IsExpired checks if the token is expired
func (c *TokenClaims) IsExpired() bool {
	return c.ExpiresAt > 0 && time.Now().Unix() > c.ExpiresAt
}

// TimeUntilExpiry returns the duration until token expiry
func (c *TokenClaims) TimeUntilExpiry() time.Duration {
	if c.ExpiresAt == 0 {
		return 0 // No expiration set
	}

	expiry := time.Unix(c.ExpiresAt, 0)
	return time.Until(expiry)
}

// IssuedTime returns the time when the token was issued
func (c *TokenClaims) IssuedTime() time.Time {
	return time.Unix(c.IssuedAt, 0)
}

// ExpiryTime returns the time when the token expires
func (c *TokenClaims) ExpiryTime() time.Time {
	if c.ExpiresAt == 0 {
		return time.Time{} // No expiration set
	}
	return time.Unix(c.ExpiresAt, 0)
}

// === Cookie helpers ========================================================

func SetAuthCookie(w http.ResponseWriter, r *http.Request, cfg *AuthConfig, token string, ttl time.Duration) {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(cfg),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func ClearAuthCookie(w http.ResponseWriter, cfg *AuthConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(cfg),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func cookieName(cfg *AuthConfig) string {
	if cfg.SessionCookieName != "" {
		return cfg.SessionCookieName
	}
	return defaultSessionCookieName
}

// corsMiddleware adds CORS headers with credentials support
func CorsMiddleware(allowOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func SetTempCookie(w http.ResponseWriter, name, val string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
}

func ExpireTempCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16]
}
