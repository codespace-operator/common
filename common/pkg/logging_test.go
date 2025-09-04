package common

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestSetLoggerAndGetLogger(t *testing.T) {
	// Replace logger
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	SetLogger(l)
	if GetLogger() != l {
		t.Fatal("GetLogger did not return the logger set via SetLogger")
	}

	// Reset to no-op by passing nil
	SetLogger(nil)
	if GetLogger() == nil {
		t.Fatal("GetLogger should never be nil")
	}
}

func TestLoggerWithContext(t *testing.T) {
	base := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := WithLogger(context.Background(), base)
	got := LoggerFromContext(ctx)
	if got != base {
		t.Fatal("LoggerFromContext did not return the stored logger")
	}
}
