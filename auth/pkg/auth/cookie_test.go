package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAMCookieTest(t *testing.T) *AuthManager {
	t.Helper()
	am, err := NewAuthManager(&AuthConfig{
		JWTSecret:         "s3cr3t",
		SessionCookieName: "codespace_session",
		SessionTTL:        2 * time.Minute,
		SameSiteMode:      http.SameSiteStrictMode,
		AuthPath:          "/auth",
		AuthLogoutPath:    "/auth/logout",
	}, nil)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	return am
}

func TestSetCookie_Session_AutoSecure_TLS(t *testing.T) {
	am := newAMCookieTest(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	// Simulate HTTPS by setting TLS field
	r.TLS = &tls.ConnectionState{}

	am.SetCookie(w, r, "codespace_session", "tok123", CookieSession, nil)

	res := w.Result()
	cs := res.Cookies()
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	c := cs[0]
	if !c.Secure {
		t.Fatal("expected Secure=true when TLS present")
	}
	if !c.HttpOnly {
		t.Fatal("expected HttpOnly=true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("want SameSite=Strict, got %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("want Path=/, got %q", c.Path)
	}
	if c.MaxAge != int((2 * time.Minute).Seconds()) {
		t.Fatalf("want MaxAge=%d, got %d", int((2 * time.Minute).Seconds()), c.MaxAge)
	}
}

func TestSetCookie_Session_AutoSecure_XFP(t *testing.T) {
	am := newAMCookieTest(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	// Simulate TLS offload at proxy
	r.Header.Set("X-Forwarded-Proto", "https")

	am.SetCookie(w, r, "codespace_session", "tok123", CookieSession, nil)

	res := w.Result()
	cs := res.Cookies()
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	if !cs[0].Secure {
		t.Fatal("expected Secure=true when X-Forwarded-Proto=https")
	}
}

func TestSetCookie_TempAuth_Profile(t *testing.T) {
	am := newAMCookieTest(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	am.SetCookie(w, r, "oidc_state", "abc", CookieTempAuth, nil)

	res := w.Result()
	cs := res.Cookies()
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	c := cs[0]
	if !c.Secure {
		t.Fatal("CookieTempAuth must always be Secure=true")
	}
	if !c.HttpOnly {
		t.Fatal("CookieTempAuth must be HttpOnly=true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("CookieTempAuth SameSite must be Strict, got %v", c.SameSite)
	}
	if c.Path != "/auth" {
		t.Fatalf("CookieTempAuth path must match AuthPath, got %q", c.Path)
	}
}

func TestClearCookie_WritesSecureAndInsecureVariants(t *testing.T) {
	am := newAMCookieTest(t)

	w := httptest.NewRecorder()
	am.ClearCookie(w, "codespace_session", CookieSession)

	res := w.Result()
	cs := res.Cookies()
	if len(cs) != 2 {
		t.Fatalf("want 2 Set-Cookie variants, got %d", len(cs))
	}
	var sawSecure, sawInsecure bool
	for _, c := range cs {
		if c.Name != "codespace_session" {
			t.Fatalf("unexpected cookie name %q", c.Name)
		}
		if c.MaxAge != -1 {
			t.Fatalf("expected deletion MaxAge=-1, got %d", c.MaxAge)
		}
		if c.Secure {
			sawSecure = true
		} else {
			sawInsecure = true
		}
	}
	if !sawSecure || !sawInsecure {
		t.Fatalf("expected both Secure and non-Secure delete variants; got secure=%v insecure=%v", sawSecure, sawInsecure)
	}
}
