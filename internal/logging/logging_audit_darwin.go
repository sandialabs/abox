//go:build darwin

package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sandialabs/abox/internal/logutil"
)

// auditFileWriter is the global rotating writer for the macOS audit log.
// It is opened by initAuditSink (called from InitWithOptions) and closed by
// closeAuditSink (called from CloseLogFile).
var (
	auditFileWriter     *logutil.RotateWriter
	auditFileWriterOnce sync.Once
	auditFilePath       string
)

// auditLogDir returns the global abox log directory under XDG_DATA_HOME.
// Matches the convention used by config.getBaseDir:
//
//	~/.local/share/abox/logs/
func auditLogDir() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "abox", "logs")
}

// initAuditSink creates the audit log directory and opens the rotating writer.
// Safe to call multiple times; only the first call acts (via sync.Once).
func initAuditSink() {
	auditFileWriterOnce.Do(func() {
		dir := auditLogDir()
		if dir == "" {
			return
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "abox: warning: cannot create audit log directory %s: %v\n", dir, err)
			return
		}
		auditFilePath = filepath.Join(dir, "audit.log")
		w, err := logutil.NewRotateWriter(auditFilePath, logutil.DefaultRotateConfig())
		if err != nil {
			fmt.Fprintf(os.Stderr, "abox: warning: cannot open audit log %s: %v\n", auditFilePath, err)
			return
		}
		auditFileWriter = w
	})
}

// closeAuditSink closes the rotating writer. Called by CloseLogFile.
func closeAuditSink() {
	if auditFileWriter != nil {
		_ = auditFileWriter.Sync()
		_ = auditFileWriter.Close()
		auditFileWriter = nil
	}
	// Reset the once so a subsequent InitWithOptions re-opens the sink.
	auditFileWriterOnce = sync.Once{}
}

// newAuditHandler returns a file-based slog.Handler for audit logging on macOS.
// Events are appended to ~/.local/share/abox/logs/audit.log.
// Returns nil if the sink could not be opened.
func newAuditHandler() slog.Handler {
	initAuditSink()
	if auditFileWriter == nil {
		return nil
	}
	return &fileAuditHandler{writer: auditFileWriter}
}

// AuditLogPath returns the absolute path of the macOS audit log file.
// Returns an empty string if the path has not been determined yet.
func AuditLogPath() string {
	return auditFilePath
}

// AuditLogHint returns the platform-appropriate command for reading audit events
// on macOS.
func AuditLogHint() string {
	p := auditFilePath
	if p == "" {
		// Fallback if InitWithOptions has not been called yet.
		dir := auditLogDir()
		if dir != "" {
			p = filepath.Join(dir, "audit.log")
		}
	}
	if p == "" {
		return "~/.local/share/abox/logs/audit.log"
	}
	return p
}

// fileAuditHandler is a slog.Handler that writes key=value lines to a rotating
// file. It is intentionally minimal: INFO level and above only, no colour, no
// structured sub-groups (the audit API is flat key/value).
type fileAuditHandler struct {
	writer *logutil.RotateWriter
	attrs  []slog.Attr
	group  string
}

func (h *fileAuditHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *fileAuditHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Time.UTC().Format(time.RFC3339))
	sb.WriteString(" level=")
	sb.WriteString(r.Level.String())
	sb.WriteString(" msg=")
	if strings.ContainsAny(r.Message, " \t\n") {
		fmt.Fprintf(&sb, "%q", r.Message)
	} else {
		sb.WriteString(r.Message)
	}

	prefix := ""
	if h.group != "" {
		prefix = h.group + "."
	}

	for _, a := range h.attrs {
		sb.WriteString(" ")
		sb.WriteString(prefix)
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(formatValue(a.Value))
	}

	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(prefix)
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(formatValue(a.Value))
		return true
	})

	sb.WriteString("\n")
	_, err := h.writer.Write([]byte(sb.String()))
	return err
}

func (h *fileAuditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &fileAuditHandler{writer: h.writer, attrs: newAttrs, group: h.group}
}

func (h *fileAuditHandler) WithGroup(name string) slog.Handler {
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &fileAuditHandler{writer: h.writer, attrs: h.attrs, group: g}
}

// auditHandlerInDefaultLogger is false on macOS: the audit file carries audit
// events only, never general operational logs.
const auditHandlerInDefaultLogger = false
