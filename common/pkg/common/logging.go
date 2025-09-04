package common

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/lmittmann/tint"
)

var (
	logger           *slog.Logger = nopLogger() // ← not nil anymore
	loggerInitOnce   sync.Once
	currentLogConfig LogConfig
)

// LogLevel represents different log levels
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// LogConfig holds logging configuration
type LogConfig struct {
	Level      LogLevel  `json:"level" yaml:"level"`
	TimeFormat string    `json:"timeFormat" yaml:"timeFormat"`
	AddSource  bool      `json:"addSource" yaml:"addSource"`
	Writer     io.Writer `json:"-" yaml:"-"`
	NoColor    bool      `json:"noColor" yaml:"noColor"`
}

func nopLogger() *slog.Logger {
	// Drop everything by default (no output, no color).
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

// SetLogger installs l as the package and process-wide default logger.
// Passing nil restores a no-op logger.
func SetLogger(l *slog.Logger) {
	if l == nil {
		l = nopLogger()
	}
	logger = l
	slog.SetDefault(l)
}

// DefaultLogConfig returns the default logging configuration
func DefaultLogConfig() LogConfig {
	return LogConfig{
		Level:      LevelInfo,
		TimeFormat: time.Kitchen, // More readable than RFC3339 for development
		AddSource:  false,
		Writer:     os.Stderr,
		NoColor:    false,
	}
}

// InitializeLogging sets up the global logger with the given configuration
func InitializeLogging(config LogConfig) *slog.Logger {
	loggerInitOnce.Do(func() {
		if config.Writer == nil {
			config.Writer = os.Stderr
		}
		SetLogger(createTintedLogger(config))
		currentLogConfig = config
	})
	return logger
}

// GetLogger returns the configured logger or creates one with defaults
func GetLogger() *slog.Logger {
	if logger == nil {
		return InitializeLogging(DefaultLogConfig())
	}
	return logger
}

// CreateLogger creates a new logger with the specified configuration
func CreateLogger(config LogConfig) *slog.Logger {
	if config.Writer == nil {
		config.Writer = os.Stderr
	}
	return createTintedLogger(config)
}

// createTintedLogger creates a new tinted slog logger
func createTintedLogger(config LogConfig) *slog.Logger {
	level := parseLogLevel(config.Level)

	opts := &tint.Options{
		Level:      level,
		TimeFormat: config.TimeFormat,
		AddSource:  config.AddSource,
		NoColor:    config.NoColor || isNoColorEnv(),
	}

	handler := tint.NewHandler(config.Writer, opts)
	return slog.New(handler)
}

// parseLogLevel converts string level to slog.Level
func parseLogLevel(level LogLevel) slog.Level {
	switch level {
	case LevelDebug:
		return slog.LevelDebug
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	case LevelInfo:
		fallthrough
	default:
		return slog.LevelInfo
	}
}

// isNoColorEnv checks environment variables that disable color output
func isNoColorEnv() bool {
	return os.Getenv("NO_COLOR") != "" ||
		os.Getenv("TERM") == "dumb" ||
		!isTerminal()
}

// isTerminal checks if stdout is a terminal (simplified version)
func isTerminal() bool {
	stat, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// LoggerWithComponent returns a logger with a component field
func LoggerWithComponent(l *slog.Logger, component string) *slog.Logger {
	if l == nil {
		l = GetLogger()
	}
	return l.With("component", component)
}

// LoggerWithRequestID returns a logger with a request ID field
func LoggerWithRequestID(logger *slog.Logger, requestID string) *slog.Logger {
	if logger == nil {
		logger = GetLogger()
	}
	return logger.With("req_id", requestID)
}

// Context-based logging utilities

type loggerKey struct{}

// WithLogger adds a logger to the context
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// LoggerFromContext retrieves a logger from context, falling back to default
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return logger
	}
	return GetLogger()
}

// ConfigureLogger is a legacy function that configures the global logger
// Deprecated: Use InitializeLogging instead
func ConfigureLogger(cfg *slog.Logger, levelStr string) {
	// This maintains backward compatibility with existing code
	level := LogLevel(levelStr)
	if level == "" {
		level = LevelInfo
	}

	config := LogConfig{
		Level:      level,
		TimeFormat: time.Kitchen,
		AddSource:  level == LevelDebug,
		Writer:     os.Stderr,
	}

	InitializeLogging(config)
}

// Development logger presets
func DevelopmentLogger() *slog.Logger {
	return CreateLogger(LogConfig{
		Level:      LevelDebug,
		TimeFormat: time.Kitchen,
		AddSource:  true,
		Writer:     os.Stderr,
		NoColor:    false,
	})
}

// Production logger presets
func ProductionLogger() *slog.Logger {
	return CreateLogger(LogConfig{
		Level:      LevelInfo,
		TimeFormat: time.RFC3339,
		AddSource:  false,
		Writer:     os.Stderr,
		NoColor:    true, // No color in production logs
	})
}

// TestLogger creates a logger suitable e2e tests
func TestLogger(writer io.Writer) *slog.Logger {
	return CreateLogger(LogConfig{
		Level:      LevelDebug,
		TimeFormat: time.Kitchen,
		AddSource:  true,
		Writer:     writer,
		NoColor:    true, // Tests usually don't need color
	})
}
