package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Log level constants
const (
	LogLevelDebug = slog.LevelDebug
	LogLevelInfo  = slog.LevelInfo
	LogLevelWarn  = slog.LevelWarn
	LogLevelError = slog.LevelError
)

type Logger struct {
	*slog.Logger
}

// LogFormat represents the logging format
type LogFormat string

const (
	FormatJSON LogFormat = "json"
	FormatText LogFormat = "text"
)

func New() *Logger {
	return NewWithFormat(FormatJSON, slog.LevelInfo)
}

func NewWithLevel(level slog.Level) *Logger {
	return NewWithFormat(FormatJSON, level)
}

func NewWithFormat(format LogFormat, level slog.Level) *Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch format {
	case FormatText:
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

// NewFromConfig creates a logger based on configuration
func NewFromConfig() *Logger {
	// Check environment variables for log format
	format := FormatJSON
	if logFormat := strings.ToLower(os.Getenv("LOG_FORMAT")); logFormat != "" {
		switch logFormat {
		case "text", "human", "console":
			format = FormatText
		case "json":
			format = FormatJSON
		}
	}

	// Check log level
	level := slog.LevelInfo
	if logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL")); logLevel != "" {
		switch logLevel {
		case "DEBUG":
			level = slog.LevelDebug
		case "INFO":
			level = slog.LevelInfo
		case "WARN", "WARNING":
			level = slog.LevelWarn
		case "ERROR":
			level = slog.LevelError
		}
	}

	return NewWithFormat(format, level)
}

// Convenience methods for common log levels
func (l *Logger) Debug(msg string, args ...any) {
	l.Logger.Debug(msg, args...)
}

func (l *Logger) Info(msg string, args ...any) {
	l.Logger.Info(msg, args...)
}

func (l *Logger) Warn(msg string, args ...any) {
	l.Logger.Warn(msg, args...)
}

func (l *Logger) Error(msg string, args ...any) {
	l.Logger.Error(msg, args...)
}

func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		Logger: l.Logger.With(args...),
	}
}
