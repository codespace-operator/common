package auth

import (
	"net/http"
	"strings"
	"time"
)

// CookieKind defines the types of cookies used for auth and/or auth flow purposes.
// It includes session cookies, temporary authentication cookies (OIDC state/nonce/pkce),
// logout hint cookies (id_token_hint), and CSRF cookies.
type CookieKind int

const (
	CookieSession    CookieKind = iota
	CookieTempAuth              // OIDC state/nonce/pkce
	CookieLogoutHint            // id_token_hint
	CookieCSRF
)

// CookieOpts specifies options for configuring cookies, such as path, max age,
// HTTP-only flag, secure flag (which can be inferred from the request if nil),
// and SameSite policy.
type CookieOpts struct {
	Path     string
	MaxAge   time.Duration
	HttpOnly bool
	Secure   *bool // nil => auto from request (TLS/XFP)
	SameSite http.SameSite
}

// ptr returns a pointer to the given value of any type.
// Used for convenience when setting pointer fields.
func ptr[T any](v T) *T { return &v }

// defaultOpts returns the default CookieOpts for a given CookieKind,
// using configuration values from AuthManager and sensible defaults.
func (am *AuthManager) defaultOpts(kind CookieKind) CookieOpts {
	switch kind {
	case CookieSession:
		return CookieOpts{
			Path:     "/",
			MaxAge:   am.config.SessionTTL,
			HttpOnly: true,
			Secure:   nil,                    // infer from request
			SameSite: am.config.SameSiteMode, // configurable
		}
	case CookieTempAuth:
		return CookieOpts{
			Path:     am.config.AuthPath,
			MaxAge:   10 * time.Minute,
			HttpOnly: true,
			Secure:   ptr(true),
			SameSite: http.SameSiteStrictMode,
		}
	case CookieLogoutHint:
		return CookieOpts{
			Path:     am.config.AuthLogoutPath,
			MaxAge:   60 * time.Second,
			HttpOnly: true,
			Secure:   ptr(true),
			SameSite: http.SameSiteStrictMode,
		}
	case CookieCSRF:
		return CookieOpts{
			Path:     "/",
			MaxAge:   2 * time.Hour,
			HttpOnly: false, // JS must read it
			Secure:   ptr(true),
			SameSite: http.SameSiteStrictMode,
		}
	default:
		return CookieOpts{Path: "/", MaxAge: time.Hour, HttpOnly: true, Secure: ptr(true), SameSite: http.SameSiteLaxMode}
	}
}

// SetCookie sets a cookie on the response writer using profile-aware defaults
// based on the specified CookieKind. Allows overriding defaults via CookieOpts.
// Automatically determines the Secure flag if not explicitly set.
func (am *AuthManager) SetCookie(w http.ResponseWriter, r *http.Request, name, value string, kind CookieKind, override *CookieOpts) {

	opts := am.defaultOpts(kind)
	if name == "" {
		// Misconfigured cookie; log and return
		am.logger.Warn("Attempted to set cookie with empty name", "name", name)
		return // do nothing if misconfigured
	}
	if override != nil {
		if override.Path != "" {
			opts.Path = override.Path
		}
		if override.MaxAge != 0 {
			opts.MaxAge = override.MaxAge
		}
		opts.HttpOnly = override.HttpOnly
		if override.SameSite != 0 {
			opts.SameSite = override.SameSite
		}
		if override.Secure != nil {
			opts.Secure = override.Secure
		}
	}
	secure := true
	if opts.Secure == nil {
		secure = r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	} else {
		secure = *opts.Secure
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     opts.Path,
		HttpOnly: opts.HttpOnly,
		Secure:   secure,
		SameSite: opts.SameSite,
		MaxAge:   int(opts.MaxAge.Seconds()),
	})
}

// ClearCookie removes a cookie by setting its value to empty and its expiration
// to the past, using profile defaults for path and flags. Writes both secure and
// non-secure variants to ensure removal regardless of how it was originally set.
func (am *AuthManager) ClearCookie(w http.ResponseWriter, name string, kind CookieKind) {
	opts := am.defaultOpts(kind)

	// secure variant
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: opts.Path, HttpOnly: opts.HttpOnly,
		Secure: true, SameSite: opts.SameSite, MaxAge: -1, Expires: time.Unix(0, 0),
	})
	// non-secure variant (covers the case it was set without Secure)
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: opts.Path, HttpOnly: opts.HttpOnly,
		Secure: false, SameSite: opts.SameSite, MaxAge: -1, Expires: time.Unix(0, 0),
	})
}
