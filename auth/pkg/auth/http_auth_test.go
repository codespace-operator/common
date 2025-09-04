package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAuthHTTPWithLocalBootstrap(t *testing.T) (*AuthHTTP, *AuthManager) {
	t.Helper()
	am, err := NewAuthManager(&AuthConfig{
		JWTSecret:         "zzz",
		SessionCookieName: "codespace_session",
		SessionTTL:        time.Minute,
		Local: &LocalConfig{
			Enabled:               true,
			BootstrapLoginAllowed: true,
			BootstrapUser:         "admin",
			BootstrapPasswd:       "adminpw",
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	return NewAuthHTTP(am, nil), am
}

func TestLocalLogin_JSONResponse(t *testing.T) {
	h, _ := newAuthHTTPWithLocalBootstrap(t)

	body := bytes.NewBufferString(`{"username":"admin","password":"adminpw"}`)
	req := httptest.NewRequest("POST", "/auth/login", body)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	h.LocalLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 OK, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("want application/json, got %q", got)
	}
	// We should get both JSON payload and a Set-Cookie (session token)
	if len(rec.Header()["Set-Cookie"]) == 0 {
		t.Fatal("expected Set-Cookie to be present")
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if payload["token"] == "" || payload["user"] != "admin" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestLocalLogin_Default204(t *testing.T) {
	h, _ := newAuthHTTPWithLocalBootstrap(t)

	body := bytes.NewBufferString(`{"username":"admin","password":"adminpw"}`)
	req := httptest.NewRequest("POST", "/auth/login", body) // no JSON preference
	rec := httptest.NewRecorder()

	h.LocalLogin(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204 No Content, got %d", rec.Code)
	}
	if len(rec.Header()["Set-Cookie"]) == 0 {
		t.Fatal("expected Set-Cookie to be present")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %q", rec.Body.String())
	}
}

func TestRefresh_AbsoluteMax_Enforced(t *testing.T) {
	h, am := newAuthHTTPWithLocalBootstrap(t)

	// Shrink the absolute max so we can trigger it.
	am.config.AbsoluteSessionMax = time.Hour

	// Craft a token whose iat is older than AbsoluteSessionMax.
	jm := am.tokenManager.(*JWTManager) // concrete type
	oldIAT := time.Now().Add(-2 * time.Hour).Unix()
	tok, err := jm.CreateToken("subX", []string{"viewer"}, "oidc", time.Minute, map[string]any{
		"username": "u",
		"email":    "u@example.com",
		"iat":      oldIAT, // override to the past
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: am.config.SessionCookieName, Value: tok})
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	// Should attempt to clear auth cookie (two variants)
	if len(rec.Header()["Set-Cookie"]) < 1 {
		t.Fatal("expected Set-Cookie headers clearing the session")
	}
}

func TestRefresh_AbsoluteMax_AllowsWithin(t *testing.T) {
	h, am := newAuthHTTPWithLocalBootstrap(t)
	am.config.AbsoluteSessionMax = 2 * time.Hour

	jm := am.tokenManager.(*JWTManager)
	recentIAT := time.Now().Add(-30 * time.Minute).Unix()
	tok, err := jm.CreateToken("subY", []string{"viewer"}, "oidc", time.Minute, map[string]any{
		"username": "u2",
		"email":    "u2@example.com",
		"iat":      recentIAT,
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: am.config.SessionCookieName, Value: tok})
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rec.Code)
	}
	// Should rotate session cookie
	if len(rec.Header()["Set-Cookie"]) == 0 {
		t.Fatal("expected Set-Cookie (rotated token)")
	}
}
