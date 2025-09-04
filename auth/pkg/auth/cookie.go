package auth

import (
	"net/http"
	"strings"
	"time"
)

type CookieKind int

const (
	CookieSession    CookieKind = iota
	CookieTempAuth              // OIDC state/nonce/pkce
	CookieLogoutHint            // id_token_hint
	CookieCSRF
)

type CookieOpts struct {
	Path     string
	MaxAge   time.Duration
	HttpOnly bool
	Secure   *bool // nil => auto from request (TLS/XFP)
	SameSite http.SameSite
}

func ptr[T any](v T) *T { return &v }

// Default profile values
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

// SetCookie centralizes all cookie writes with profile-aware defaults.
func (am *AuthManager) SetCookie(w http.ResponseWriter, r *http.Request, name, value string, kind CookieKind, override *CookieOpts) {
	opts := am.defaultOpts(kind)
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

// ClearCookie clears a cookie using its profile defaults (path/flags).
func (am *AuthManager) ClearCookie(w http.ResponseWriter, name string, kind CookieKind) {
	opts := am.defaultOpts(kind)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     opts.Path,
		HttpOnly: opts.HttpOnly,
		Secure:   opts.Secure == nil || *opts.Secure,
		SameSite: opts.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}
