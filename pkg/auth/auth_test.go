package auth

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionJWT(t *testing.T) {
	secret := []byte("test-secret")
	token, err := MakeJWT("u123", []string{"group-a"}, "oidc", secret, time.Minute, map[string]any{"email": "u@example.com"})
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}
	c, err := parseJWT(token, secret)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}
	if c.Sub != "u123" || c.Email != "u@example.com" || c.Provider != "oidc" {
		t.Fatalf("claims mismatch: %+v", c)
	}

	// Expiry
	expired, _ := MakeJWT("u", nil, "oidc", secret, -1*time.Second, nil)
	if _, err := parseJWT(expired, secret); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestRequireAPIToken_Cookie(t *testing.T) {
	cfg := &AuthConfig{
		JWTSecret:         "zzz",
		SessionCookieName: "codespace_session",
	}
	token, _ := MakeJWT("sub", []string{"r"}, "oidc", []byte(cfg.JWTSecret), time.Minute, nil)

	h := RequireAPIToken(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl := FromContext(r) // Fixed: use FromContext instead of fromContext
		if cl == nil || cl.Sub != "sub" {
			t.Fatalf("missing claims in context")
		}
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestStateCookie(t *testing.T) {
	// simple check for secure attributes
	w := httptest.NewRecorder()
	SetTempCookie(w, OIDCStateCookie, "state")
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || !c.Secure || c.MaxAge <= 0 {
		t.Fatalf("want secure short-lived cookie, got %#v", c)
	}
}

func TestJWTManager(t *testing.T) {
	// Use slog.Logger for NewJWTManager
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	jwtManager, err := NewJWTManager("test-secret", logger)
	if err != nil {
		t.Fatalf("NewJWTManager failed: %v", err)
	}

	token, err := jwtManager.CreateToken("test-user", []string{"admin"}, "test", time.Hour, map[string]any{"email": "test@example.com"})
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	claims, err := jwtManager.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Sub != "test-user" {
		t.Fatalf("Expected subject 'test-user', got %s", claims.Sub)
	}
}
