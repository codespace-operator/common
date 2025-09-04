package auth

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func writeLocalUsers(t *testing.T, dir string) string {
	t.Helper()
	pw, _ := bcrypt.GenerateFromPassword([]byte("alicepw"), bcrypt.DefaultCost)
	// keep yaml minimal and deterministic
	data := []byte(`users:
  - username: alice
    passwordHash: "` + string(pw) + `"
    email: alice@example.com
    roles: ["editor"]
`)
	p := filepath.Join(dir, "users.yaml")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	return p
}

func TestLocalProvider_FileUsersAndBootstrap(t *testing.T) {
	dir := t.TempDir()
	usersPath := writeLocalUsers(t, dir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tm, _ := NewJWTManager("test-secret", logger)

	lp, err := NewLocalProvider(&LocalConfig{
		Enabled:               true,
		UsersPath:             usersPath,
		BootstrapLoginAllowed: true,
		BootstrapUser:         "admin",
		BootstrapPasswd:       "adminpw",
	}, tm, logger, nil)
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	// File-based user
	claims, err := lp.Authenticate("alice", "alicepw")
	if err != nil {
		t.Fatalf("Authenticate(file): %v", err)
	}
	if claims.Username != "alice" || claims.Provider != LOCAL_PROVIDER {
		t.Fatalf("claims mismatch: %+v", claims)
	}

	// Bootstrap user
	claims, err = lp.Authenticate("admin", "adminpw")
	if err != nil {
		t.Fatalf("Authenticate(bootstrap): %v", err)
	}
	if claims.Username != "admin" || claims.Roles[0] != "admin" {
		t.Fatalf("bootstrap claims mismatch: %+v", claims)
	}

	// Issue session from AuthManager to ensure end-to-end
	am, _ := NewAuthManager(&AuthConfig{
		JWTSecret:  "test-secret",
		SessionTTL: 2 * time.Minute,
		Local: &LocalConfig{
			Enabled:               true,
			UsersPath:             usersPath,
			BootstrapLoginAllowed: true,
			BootstrapUser:         "admin",
			BootstrapPasswd:       "adminpw",
		},
	}, logger)
	if am.GetLocalProvider() == nil {
		t.Fatal("expected local provider enabled")
	}
}
