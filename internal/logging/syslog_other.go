//go:build !linux && !darwin

package logging

import "log/slog"

// newSyslogHandler returns nil on platforms without a syslog audit sink (e.g.
// Windows). Audit logging falls back to the discard handler, matching the
// behavior when the syslog daemon is unreachable on Linux. macOS does not build
// this file — it uses the unified-log sink (audit_darwin.go) instead.
func newSyslogHandler() slog.Handler {
	return nil
}
