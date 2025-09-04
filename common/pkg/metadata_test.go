package common

import (
	"strings"
	"testing"
)

func TestSanitizeLabelValue(t *testing.T) {
	t.Run("empty->unknown", func(t *testing.T) {
		if got := SanitizeLabelValue(""); got != "unknown" {
			t.Fatalf("want unknown, got %q", got)
		}
	})

	t.Run("invalid chars are dashed and trimmed", func(t *testing.T) {
		in := "..___$$$Weird--name###..."
		got := SanitizeLabelValue(in)
		if got != "Weird--name" { // trims leading/trailing -_. and maps others to '-'
			t.Fatalf("want %q, got %q", "Weird--name", got)
		}
	})

	t.Run("truncates >63 and appends tiny hash", func(t *testing.T) {
		long := strings.Repeat("a", 70) // definitely >63
		got := SanitizeLabelValue(long)

		// Must truncate to 60 + 2 hex chars from K8sHexHash(value, 1) = 62 total.
		if len(got) != 62 {
			t.Fatalf("want length 62, got %d (%q)", len(got), got)
		}
		wantSuffix := K8sHexHash(long, 1)
		if got[len(got)-len(wantSuffix):] != wantSuffix {
			t.Fatalf("want suffix %q, got %q", wantSuffix, got)
		}
	})

}
