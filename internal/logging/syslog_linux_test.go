//go:build linux

package logging

import (
	"log/slog"
	"testing"
)

// TestSyslogHandlerWithAttrs tests WithAttrs on syslog handler.
func TestSyslogHandlerWithAttrs(t *testing.T) {
	handler := newSyslogHandler()
	if handler == nil {
		t.Skip("syslog not available on this system")
	}

	withAttrs := handler.WithAttrs([]slog.Attr{slog.String("component", "test")})

	// Verify the new handler has the attrs
	sh, ok := withAttrs.(*syslogHandler)
	if !ok {
		t.Fatal("expected syslogHandler type")
	}

	if len(sh.attrs) != 1 {
		t.Errorf("expected 1 attr, got %d", len(sh.attrs))
	}
}

// TestSyslogHandlerWithGroup tests WithGroup on syslog handler.
func TestSyslogHandlerWithGroup(t *testing.T) {
	handler := newSyslogHandler()
	if handler == nil {
		t.Skip("syslog not available on this system")
	}

	withGroup := handler.WithGroup("mygroup")

	sh, ok := withGroup.(*syslogHandler)
	if !ok {
		t.Fatal("expected syslogHandler type")
	}

	if sh.group != "mygroup" {
		t.Errorf("expected group 'mygroup', got %q", sh.group)
	}

	// Test nested groups
	withGroup2 := sh.WithGroup("nested")
	sh2, ok := withGroup2.(*syslogHandler)
	if !ok {
		t.Fatal("expected syslogHandler type")
	}

	if sh2.group != "mygroup.nested" {
		t.Errorf("expected group 'mygroup.nested', got %q", sh2.group)
	}
}
