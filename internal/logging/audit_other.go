//go:build !linux && !darwin

package logging

import "log/slog"

// newAuditHandler falls back to the (nil) syslog handler on platforms without a
// dedicated audit sink (e.g. Windows), so audit logging degrades to discard just
// as it does when syslog is unreachable on Unix.
func newAuditHandler() slog.Handler {
	return newSyslogHandler()
}

// initAuditSink is a no-op: there is no file/directory sink to prepare.
func initAuditSink() {}

// closeAuditSink is a no-op: there is no dedicated sink to close.
func closeAuditSink() {}

// AuditLogHint returns a platform-neutral hint.
func AuditLogHint() string {
	return "(audit logging is not available on this platform)"
}

// AuditLogPath returns the audit log path; unavailable on this platform.
func AuditLogPath() string {
	return "(unavailable)"
}

// auditHandlerInDefaultLogger is false: no audit handler to route default logs through.
const auditHandlerInDefaultLogger = false
