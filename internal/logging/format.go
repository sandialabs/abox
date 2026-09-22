package logging

import (
	"fmt"
	"log/slog"
	"strings"
)

// formatValue formats a slog.Value for a key=value audit line. It is shared by
// the platform audit handlers (syslog on Linux, the unified log via logger on
// macOS).
func formatValue(v slog.Value) string {
	switch v.Kind() { //nolint:exhaustive // default handles all non-string kinds via v.Any()
	case slog.KindString:
		s := v.String()
		// Quote strings containing whitespace. Crucially this includes CR and LF:
		// audit records are one-per-line (in syslog and the macOS unified log), so
		// an un-escaped CR/LF in an attacker-influenced value (e.g. an HTTP Host
		// header or CLI arg) could forge a second record. %q escapes them.
		if strings.ContainsAny(s, " \t\n\r") {
			return fmt.Sprintf("%q", s)
		}
		return s
	default:
		// Non-string kinds (errors, []byte, fmt.Stringer, ...) can also render with
		// embedded whitespace/CR/LF, so apply the same quoting rather than relying
		// on a caller to strip it — keeps the safety local to this function.
		s := fmt.Sprintf("%v", v.Any())
		if strings.ContainsAny(s, " \t\n\r") {
			return fmt.Sprintf("%q", s)
		}
		return s
	}
}
