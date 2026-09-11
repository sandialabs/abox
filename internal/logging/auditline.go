package logging

import (
	"fmt"
	"log/slog"
	"strings"
)

// sanitizeToken makes a bare token — an audit key or the record message — safe to
// embed in a single-line audit record. Anything containing whitespace, crucially
// CR/LF (which would otherwise forge a second log record), is quoted via %q so the
// control bytes are escaped. Values go through formatValue, which applies the same
// rule.
func sanitizeToken(s string) string {
	if strings.ContainsAny(s, " \t\n\r") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// stripCRLF removes any residual carriage return / newline from a fully assembled
// audit line. Defense in depth: sanitizeToken and formatValue already escape CR/LF
// in every field, so a well-formed line has none — this guarantees one record per
// line even if an unsanitized field is ever added later.
func stripCRLF(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// appendAuditAttrs writes " key=value" for each handler-level attr then each
// record attr, with keys sanitized and values hardened via formatValue. Shared by
// the darwin unified-log handler and the linux syslog handler so both platforms
// get identical injection-safe formatting.
func appendAuditAttrs(sb *strings.Builder, group string, attrs []slog.Attr, r slog.Record) {
	prefix := ""
	if group != "" {
		prefix = group + "."
	}
	write := func(a slog.Attr) {
		sb.WriteString(" ")
		sb.WriteString(prefix)
		sb.WriteString(sanitizeToken(a.Key))
		sb.WriteString("=")
		sb.WriteString(formatValue(a.Value))
	}
	for _, a := range attrs {
		write(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		write(a)
		return true
	})
}

// formatAuditLine builds the injection-safe body of a macOS audit record:
//
//	level=<LEVEL> msg=<msg> key=value ...
//
// The message and keys are sanitized and values quoted so no attacker-influenced
// field can inject a CR/LF and forge a second record; the returned string is
// guaranteed free of CR/LF. The darwin handler prepends the "abox" sentinel and a
// UTC timestamp. This body is what the portable CI-visible test asserts on.
func formatAuditLine(r slog.Record, attrs []slog.Attr, group string) string {
	var sb strings.Builder
	sb.WriteString("level=")
	sb.WriteString(r.Level.String())
	sb.WriteString(" msg=")
	sb.WriteString(sanitizeToken(r.Message))
	appendAuditAttrs(&sb, group, attrs, r)
	return stripCRLF(sb.String())
}
