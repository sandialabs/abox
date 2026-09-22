package logging

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestFormatAuditLineFields checks the shared audit line builder emits the level,
// message, and attributes. This runs on the Linux `test` job (the darwin handler
// test does not), so it is where the format is actually exercised in CI.
func TestFormatAuditLineFields(t *testing.T) {
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "instance.start", 0)
	r.AddAttrs(slog.String("instance", "dev"), slog.String("user", "alice"))

	line := formatAuditLine(r, nil, "")
	for _, want := range []string{"level=INFO", "msg=instance.start", "instance=dev", "user=alice"} {
		if !strings.Contains(line, want) {
			t.Errorf("formatAuditLine missing %q; got: %s", want, line)
		}
	}
}

// TestFormatAuditLineGroupPrefix checks handler-group prefixing of keys.
func TestFormatAuditLineGroupPrefix(t *testing.T) {
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "msg", 0)
	line := formatAuditLine(r, []slog.Attr{slog.String("k", "v")}, "grp")
	if !strings.Contains(line, "grp.k=v") {
		t.Errorf("expected group-prefixed key grp.k=v; got: %s", line)
	}
}

// TestFormatAuditLineInjectionSafe verifies attacker-influenced values (and keys /
// message) with embedded CR/LF cannot forge a second audit record: the assembled
// line must contain no raw CR/LF.
func TestFormatAuditLineInjectionSafe(t *testing.T) {
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "http.block\nabox forged=msg", 0)
	r.AddAttrs(
		slog.String("host", "evil\r\nabox forged=value"),
		slog.String("weird\nkey", "x"),
	)

	line := formatAuditLine(r, nil, "")
	if strings.ContainsAny(line, "\r\n") {
		t.Errorf("formatAuditLine must not contain raw CR/LF; got: %q", line)
	}
	if !strings.Contains(line, "host=") {
		t.Errorf("expected host= in line; got: %s", line)
	}
}
