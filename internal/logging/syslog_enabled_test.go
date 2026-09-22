//go:build !darwin

package logging

import (
	"context"
	"log/slog"
	"testing"
)

// TestSyslogHandlerEnabled checks the syslog audit handler's level gating.
// macOS uses the unified-log audit sink instead of syslog (see audit_darwin.go),
// so this is gated to non-darwin platforms.
func TestSyslogHandlerEnabled(t *testing.T) {
	// Create a handler (may be nil if syslog is unavailable)
	handler := newSyslogHandler()
	if handler == nil {
		t.Skip("syslog not available on this system")
	}

	// Debug should not be enabled
	if handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be disabled for syslog handler")
	}

	// Info should be enabled
	if !handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info to be enabled for syslog handler")
	}

	// Warn should be enabled
	if !handler.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("expected warn to be enabled for syslog handler")
	}

	// Error should be enabled
	if !handler.Enabled(context.Background(), slog.LevelError) {
		t.Error("expected error to be enabled for syslog handler")
	}
}
