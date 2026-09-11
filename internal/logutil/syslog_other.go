//go:build !unix

package logutil

// logError is a no-op on platforms without syslog (Windows). Rotation errors
// are non-fatal and already surfaced through returned errors where it matters.
func logError(_ string, _ error) {}
