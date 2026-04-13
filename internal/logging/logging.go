// Package logging provides structured logging for abox using slog.
// It supports dual output: stderr for users and syslog for audit trails.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sandialabs/abox/internal/iostreams"
)

// currentUser caches the username for audit logging.
var currentUser string

// logFileHandle holds the open log file for cleanup.
var logFileHandle *os.File

// logLevel is the package-level LevelVar for runtime log level changes.
var logLevel = new(slog.LevelVar)

// auditLogger is a syslog-only logger used by Audit(). Audit events go to
// syslog (journalctl -t abox) and never appear on stderr. Initialized with a
// discard handler so Audit() is safe to call before Init(); Init() replaces
// this with the real syslog handler.
var auditLogger = slog.New(discardHandler{})

// stderrWriter is a swappable writer used by the slog stderr handler.
// The TUI swaps it to redirect log output into the TUI log panel during
// execution, then swaps it back when the TUI exits.
var stderrWriter = iostreams.NewSafeWriter(os.Stderr)

func init() {
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	} else {
		currentUser = "unknown"
	}
}

// Options configures logging initialization.
type Options struct {
	Level   slog.Level
	LogFile string // Path to log file (optional, logs to file in addition to stderr)
	Format  string // "text" (default) or "json"
}

// DefaultOptions provides sensible defaults for logging configuration.
var DefaultOptions = Options{
	Level:  slog.LevelInfo,
	Format: "text",
}

// InitWithOptions initializes the global logger with the specified options.
// If LogFile is set, logs are written to the file in addition to stderr.
// Audit logging to syslog is always enabled at INFO level.
func InitWithOptions(opts Options) error {
	// Close any existing log file
	CloseLogFile()

	// Set the initial level from options
	logLevel.Set(opts.Level)

	handlerOpts := &slog.HandlerOptions{
		Level: logLevel,
	}

	stderrHandler := newLogHandler(stderrWriter, handlerOpts, opts.Format)

	handlers := []slog.Handler{stderrHandler}

	// Add file handler if LogFile is specified
	if opts.LogFile != "" {
		fileHandler, err := openLogFileHandler(opts.LogFile, logLevel, opts.Format)
		if err != nil {
			return err
		}
		handlers = append(handlers, fileHandler)
	}

	// Create syslog handler for audit logging (always INFO level, never disabled)
	syslogHandler := newSyslogHandler()
	if syslogHandler != nil {
		handlers = append(handlers, syslogHandler)
		auditLogger = slog.New(syslogHandler)
	} else {
		auditLogger = slog.New(discardHandler{})
	}

	// Multi-handler: writes to all handlers
	handler := slog.Handler(&multiHandler{handlers: handlers})
	if len(handlers) == 1 {
		handler = handlers[0]
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return nil
}

func openLogFileHandler(logFile string, level slog.Leveler, format string) (slog.Handler, error) {
	logPath := logFile
	if strings.HasPrefix(logPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to expand home directory: %w", err)
		}
		logPath = filepath.Join(home, logPath[2:])
	}

	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // log dir needs 0o755 for user access
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	logFileHandle = f

	return newLogHandler(f, &slog.HandlerOptions{Level: level}, format), nil
}

// StderrWriter returns the swappable writer used by the slog stderr handler.
// The TUI uses this to redirect slog output during TUI execution:
//
//	old := logging.StderrWriter().Swap(tuiWriter)
//	defer logging.StderrWriter().Swap(old)
func StderrWriter() *iostreams.SafeWriter {
	return stderrWriter
}

// newLogHandler creates a JSON or text slog handler based on the format string.
func newLogHandler(w io.Writer, opts *slog.HandlerOptions, format string) slog.Handler {
	if strings.ToLower(format) == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// CloseLogFile closes the log file if one is open.
func CloseLogFile() {
	if logFileHandle != nil {
		if err := logFileHandle.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close log file: %v\n", err)
		}
		logFileHandle = nil
	}
}

const levelInfo = "info"

// ParseLevel parses a log level string and returns the corresponding slog.Level.
// Valid values are "debug", "info", "warn"/"warning", and "error".
// Returns slog.LevelInfo for empty or invalid values.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case levelInfo, "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// SetLevel changes the log level at runtime.
func SetLevel(level slog.Level) {
	logLevel.Set(level)
}

// GetLevel returns the current log level.
func GetLevel() slog.Level {
	return logLevel.Level()
}

// LevelString returns the string representation of the current log level.
func LevelString(level slog.Level) string {
	switch level {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return levelInfo
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return levelInfo
	}
}

// ValidLevels are the accepted log level values.
var ValidLevels = []string{"debug", "info", "warn", "error"}

// IsValidLevel returns true if the given level string is a valid log level.
func IsValidLevel(level string) bool {
	return slices.Contains(ValidLevels, level)
}

// SetLevelString sets the log level from a string and returns a confirmation message.
func SetLevelString(level string) string {
	l := ParseLevel(level)
	SetLevel(l)
	return "log level set to " + LevelString(l)
}

// GetLevelString returns the current log level as a string.
func GetLevelString() string {
	return LevelString(GetLevel())
}

// Debug logs a debug-level message.
func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

// Warn logs a warning-level message.
func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// Audit logs an audit message to syslog only (not stderr).
// The current user is automatically included. Use this for
// security-relevant operations that should be tracked.
// View with: journalctl -t abox
func Audit(msg string, args ...any) {
	args = append(args, "user", currentUser)
	auditLogger.Info(msg, args...)
}

// discardHandler is a no-op slog.Handler used when syslog is unavailable.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler        { return discardHandler{} }
func (discardHandler) WithGroup(string) slog.Handler             { return discardHandler{} }

// multiHandler implements slog.Handler and writes to multiple handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			if err := handler.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithAttrs(attrs)
	}
	return &multiHandler{handlers: newHandlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithGroup(name)
	}
	return &multiHandler{handlers: newHandlers}
}

// syslogHandler implements slog.Handler and writes to syslog.
type syslogHandler struct {
	writer *syslog.Writer
	attrs  []slog.Attr
	group  string
}

// newSyslogHandler creates a syslog handler for audit logging.
// Returns nil if syslog is unavailable (e.g., on non-Unix systems).
func newSyslogHandler() *syslogHandler {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "abox")
	if err != nil {
		return nil
	}
	return &syslogHandler{writer: w}
}

func (h *syslogHandler) Enabled(_ context.Context, level slog.Level) bool {
	// Syslog handler only logs INFO and above (no debug spam)
	return level >= slog.LevelInfo
}

func (h *syslogHandler) Handle(_ context.Context, r slog.Record) error {
	// Format message as key=value pairs
	var sb strings.Builder
	sb.WriteString(r.Message)

	// Add group prefix if set
	prefix := ""
	if h.group != "" {
		prefix = h.group + "."
	}

	// Add handler-level attrs
	for _, attr := range h.attrs {
		sb.WriteString(" ")
		sb.WriteString(prefix)
		sb.WriteString(attr.Key)
		sb.WriteString("=")
		sb.WriteString(formatValue(attr.Value))
	}

	// Add record attrs
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(prefix)
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(formatValue(a.Value))
		return true
	})

	msg := sb.String()

	// Write to appropriate syslog level
	switch r.Level {
	case slog.LevelDebug:
		return h.writer.Debug(msg)
	case slog.LevelInfo:
		return h.writer.Info(msg)
	case slog.LevelWarn:
		return h.writer.Warning(msg)
	case slog.LevelError:
		return h.writer.Err(msg)
	default:
		return h.writer.Info(msg)
	}
}

func (h *syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &syslogHandler{
		writer: h.writer,
		attrs:  newAttrs,
		group:  h.group,
	}
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	newGroup := name
	if h.group != "" {
		newGroup = h.group + "." + name
	}
	return &syslogHandler{
		writer: h.writer,
		attrs:  h.attrs,
		group:  newGroup,
	}
}

// formatValue formats a slog.Value for output.
func formatValue(v slog.Value) string {
	switch v.Kind() { //nolint:exhaustive // default handles all non-string kinds via v.Any()
	case slog.KindString:
		s := v.String()
		// Quote strings containing spaces
		if strings.ContainsAny(s, " \t\n") {
			return fmt.Sprintf("%q", s)
		}
		return s
	default:
		return fmt.Sprintf("%v", v.Any())
	}
}
