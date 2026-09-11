//go:build linux

package logging

import (
	"context"
	"log/slog"
	"log/syslog"
	"strings"
)

// syslogHandler implements slog.Handler and writes to syslog.
type syslogHandler struct {
	writer *syslog.Writer
	attrs  []slog.Attr
	group  string
}

// newSyslogHandler creates a syslog handler for audit logging.
// Returns nil if syslog is unavailable (e.g., syslog daemon not reachable).
func newSyslogHandler() slog.Handler {
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
	// Format message as "<msg> key=value ..." — the bare message (preserving the
	// long-standing `journalctl -t abox` output), then attrs via the shared builder
	// (sanitizes keys, quotes/escapes CR/LF in values). syslog supplies its own
	// timestamp/priority envelope. stripCRLF over the whole line is the CR/LF
	// injection backstop; the message itself is a developer-controlled action
	// string, not attacker input.
	var sb strings.Builder
	sb.WriteString(r.Message)
	appendAuditAttrs(&sb, h.group, h.attrs, r)
	msg := stripCRLF(sb.String())

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
