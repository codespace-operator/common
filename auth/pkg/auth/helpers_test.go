package auth

import (
	"net/http/httptest"
	"testing"
)

func TestIssuerIDFromURL(t *testing.T) {
	got := issuerIDFromURL("https://keycloak.example.com/realms/prod")
	want := "keycloak.example.com~realms~prod"
	if got != want {
		t.Fatalf("issuerIDFromURL mismatch: got %q want %q", got, want)
	}

	// malformed URL should fallback to hash (length 16)
	got = issuerIDFromURL("%%% bad %%%")
	if len(got) != 16 {
		t.Fatalf("expected short hash of length 16, got %q (len %d)", got, len(got))
	}
}

func TestIsSafeRedirect(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/ok", true},
		{"/path/with?q=1", true},
		{"//evil.com", false},
		{"http://evil.com", false},
		{"", false},
	}
	for _, c := range cases {
		if isSafeRedirect(c.in) != c.want {
			t.Fatalf("isSafeRedirect(%q)=%v want %v", c.in, !c.want, c.want)
		}
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("a", "a") {
		t.Fatal("expected equal strings to be constantTimeEqual")
	}
	if constantTimeEqual("a", "b") {
		t.Fatal("expected different strings to be not equal")
	}
}

func TestExtractTokenFromRequest_Misconfig(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if tok, err := ExtractTokenFromRequest(r, "", true); tok != "" || err == nil {
		t.Fatalf("expected error when cookieName is empty, got tok=%q err=%v", tok, err)
	}
}
