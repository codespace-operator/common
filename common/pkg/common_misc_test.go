package common

import (
	"encoding/base64"
	"testing"
)

func TestRandB64(t *testing.T) {
	s1 := RandB64(16)
	s2 := RandB64(16)
	if s1 == s2 {
		t.Fatal("RandB64 should produce different values")
	}
	if _, err := base64.RawURLEncoding.DecodeString(s1); err != nil {
		t.Fatalf("RandB64 not base64: %v", err)
	}
}

func TestItoa(t *testing.T) {
	if Itoa(42) != "42" {
		t.Fatalf("Itoa(42) => %q", Itoa(42))
	}
}

func TestSubjectToLabelID(t *testing.T) {
	id := SubjectToLabelID("user:alice@example.com")
	if id == "" || len(id) != 45 || id[:5] != "s256-" {
		t.Fatalf("bad label id: %q", id)
	}
	// stable for same input
	if SubjectToLabelID("user:alice@example.com") != id {
		t.Fatal("SubjectToLabelID should be stable for same input")
	}
}
