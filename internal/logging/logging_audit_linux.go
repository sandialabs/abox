//go:build linux

package logging

import "log/slog"

// newAuditHandler returns a syslog-backed slog.Handler for audit logging on Linux.
// Events are written to syslog and are readable via:
//
//	journalctl -t abox
//
// Returns nil if syslog is unavailable.
func newAuditHandler() slog.Handler {
	return newSyslogHandler()
}

// initAuditSink is a no-op on Linux because syslog requires no directory setup.
func initAuditSink() {}

// closeAuditSink is a no-op on Linux because the syslog writer is managed by newSyslogHandler.
func closeAuditSink() {}

// AuditLogHint returns the platform-appropriate hint for reading audit events.
func AuditLogHint() string {
	return "journalctl -t abox             All abox audit events\n" +
		"  journalctl -t abox --since \"1 hour ago\""
}

// AuditLogPath returns the audit log path; on Linux audit events go to syslog.
func AuditLogPath() string {
	return "(syslog)"
}

// auditHandlerInDefaultLogger preserves the historical Linux behavior of also
// routing the default logger's INFO+ output through the syslog handler.
const auditHandlerInDefaultLogger = true
