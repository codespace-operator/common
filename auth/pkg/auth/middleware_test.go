package auth

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractTokenFromRequest_Order(t *testing.T) {
	// Cookie first
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "codespace_session", Value: "cookieTok"})
	if tok := ExtractTokenFromRequest(r, "codespace_session", true); tok != "cookieTok" {
		t.Fatalf("want cookieTok, got %q", tok)
	}

	// Authorization header
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer headerTok")
	if tok := ExtractTokenFromRequest(r, "codespace_session", true); tok != "headerTok" {
		t.Fatalf("want headerTok, got %q", tok)
	}

	// Query param (only when allowed)
	r = httptest.NewRequest("GET", "/?access_token=urlTok", nil)
	if tok := ExtractTokenFromRequest(r, "codespace_session", false); tok != "" {
		t.Fatalf("url param should be disabled, got %q", tok)
	}
	if tok := ExtractTokenFromRequest(r, "codespace_session", true); tok != "urlTok" {
		t.Fatalf("want urlTok, got %q", tok)
	}
}

func newAuthManagerForTest(t *testing.T) *AuthManager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	am, err := NewAuthManager(&AuthConfig{
		JWTSecret:         "zzz",
		SessionCookieName: "codespace_session",
		SessionTTL:        time.Minute,
	}, logger)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	return am
}

func TestMiddleware_RequireAuth_AllowsValid(t *testing.T) {
	am := newAuthManagerForTest(t)
	token, _ := am.tokenManager.CreateToken("sub123", []string{"viewer"}, "oidc", time.Minute, nil)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cl := FromContext(r); cl == nil || cl.Sub != "sub123" {
			t.Fatalf("missing/invalid claims in context: %+v", cl)
		}
		w.WriteHeader(200)
	})

	mw := NewMiddleware(am, nil).RequireAuth(protected)

	req := httptest.NewRequest("GET", "/api/thing", nil)
	req.AddCookie(&http.Cookie{Name: "codespace_session", Value: token})
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestMiddleware_RequireAuth_RejectsMissing(t *testing.T) {
	am := newAuthManagerForTest(t)
	protected := NewMiddleware(am, nil).RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/api/thing", nil)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}
