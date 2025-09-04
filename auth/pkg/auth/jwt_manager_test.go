package auth

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func newJWTMForTest(t *testing.T) TokenManager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := NewJWTManager("test-secret", logger)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return m
}

func TestJWTManager_CreateAndValidate(t *testing.T) {
	jwtm := newJWTMForTest(t)

	token, err := jwtm.CreateToken("user-1", []string{"viewer"}, "oidc", time.Minute, map[string]any{
		"email":    "u1@example.com",
		"username": "u1",
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	claims, err := jwtm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if claims.Sub != "user-1" || claims.Provider != "oidc" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if claims.IsExpired() {
		t.Fatal("token should not be expired")
	}
}

func TestJWTManager_Expired(t *testing.T) {
	jwtm := newJWTMForTest(t)

	token, err := jwtm.CreateToken("user-2", nil, "oidc", -1*time.Second, nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if _, err := jwtm.ValidateToken(token); err == nil {
		t.Fatal("expected ErrExpiredToken")
	}
}

func TestJWTManager_Refresh(t *testing.T) {
	jwtm := newJWTMForTest(t)
	token, err := jwtm.CreateToken("user-3", []string{"editor"}, "oidc", time.Second, map[string]any{
		"email": "u3@example.com",
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	newTok, err := jwtm.RefreshToken(token, time.Minute)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}

	claims, err := jwtm.ValidateToken(newTok)
	if err != nil {
		t.Fatalf("ValidateToken(new): %v", err)
	}
	if claims.Sub != "user-3" || claims.Email != "u3@example.com" {
		t.Fatalf("refreshed claims mismatch: %+v", claims)
	}
	if claims.TimeUntilExpiry() <= 0 {
		t.Fatal("refreshed token should have positive TTL")
	}
}
