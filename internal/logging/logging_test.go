package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestInitWithOptions tests that InitWithOptions properly configures the logger.
func TestInitWithOptions(t *testing.T) {
	err := InitWithOptions(DefaultOptions)
	if err != nil {
		t.Fatalf("InitWithOptions failed: %v", err)
	}

	// Verify the default logger is set
	logger := slog.Default()
	if logger == nil {
		t.Fatal("expected default logger to be set")
	}
}

// TestMultiHandler tests the multiHandler implementation.
func TestMultiHandler(t *testing.T) {
	// Create two test handlers that record what they receive
	var buf1, buf2 bytes.Buffer
	h1 := slog.NewTextHandler(&buf1, &slog.HandlerOptions{Level: slog.LevelInfo})
	h2 := slog.NewTextHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelInfo})

	multi := &multiHandler{handlers: []slog.Handler{h1, h2}}

	// Create a logger with the multi-handler
	logger := slog.New(multi)

	// Log a message
	logger.Info("test message", "key", "value")

	// Both handlers should have received the message
	if !strings.Contains(buf1.String(), "test message") {
		t.Errorf("handler 1 should contain 'test message', got: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "test message") {
		t.Errorf("handler 2 should contain 'test message', got: %s", buf2.String())
	}
}

// TestMultiHandlerEnabled tests that Enabled returns true if any handler is enabled.
func TestMultiHandlerEnabled(t *testing.T) {
	// Create handlers with different levels
	debugHandler := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	infoHandler := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})

	multi := &multiHandler{handlers: []slog.Handler{debugHandler, infoHandler}}

	// Debug should be enabled because debugHandler accepts it
	if !multi.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be enabled when one handler accepts it")
	}

	// Info should be enabled
	if !multi.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info to be enabled")
	}

	// Error should be enabled
	if !multi.Enabled(context.Background(), slog.LevelError) {
		t.Error("expected error to be enabled")
	}
}

// TestMultiHandlerWithAttrs tests WithAttrs on multiHandler.
func TestMultiHandlerWithAttrs(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := slog.NewTextHandler(&buf1, &slog.HandlerOptions{Level: slog.LevelInfo})
	h2 := slog.NewTextHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelInfo})

	multi := &multiHandler{handlers: []slog.Handler{h1, h2}}
	withAttrs := multi.WithAttrs([]slog.Attr{slog.String("component", "test")})

	logger := slog.New(withAttrs)
	logger.Info("test message")

	// Both outputs should contain the component attribute
	if !strings.Contains(buf1.String(), "component") {
		t.Errorf("handler 1 should contain 'component', got: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "component") {
		t.Errorf("handler 2 should contain 'component', got: %s", buf2.String())
	}
}

// TestMultiHandlerWithGroup tests WithGroup on multiHandler.
func TestMultiHandlerWithGroup(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := slog.NewJSONHandler(&buf1, &slog.HandlerOptions{Level: slog.LevelInfo})
	h2 := slog.NewJSONHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelInfo})

	multi := &multiHandler{handlers: []slog.Handler{h1, h2}}
	withGroup := multi.WithGroup("mygroup")

	logger := slog.New(withGroup)
	logger.Info("test message", "key", "value")

	// Both outputs should contain the group
	if !strings.Contains(buf1.String(), "mygroup") {
		t.Errorf("handler 1 should contain 'mygroup', got: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "mygroup") {
		t.Errorf("handler 2 should contain 'mygroup', got: %s", buf2.String())
	}
}

// TestFormatValue tests the formatValue helper function.
func TestFormatValue(t *testing.T) {
	tests := []struct {
		name     string
		value    slog.Value
		expected string
	}{
		{
			name:     "simple string",
			value:    slog.StringValue("hello"),
			expected: "hello",
		},
		{
			name:     "string with spaces",
			value:    slog.StringValue("hello world"),
			expected: `"hello world"`,
		},
		{
			name:     "integer",
			value:    slog.IntValue(42),
			expected: "42",
		},
		{
			name:     "boolean",
			value:    slog.BoolValue(true),
			expected: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatValue(tt.value)
			if result != tt.expected {
				t.Errorf("formatValue(%v) = %q, want %q", tt.value, result, tt.expected)
			}
		})
	}
}

// TestLoggingFunctions tests the convenience logging functions.
func TestLoggingFunctions(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))

	// Test each logging function
	Debug("debug message", "key", "value")
	if !strings.Contains(buf.String(), "debug message") {
		t.Error("expected debug message in output")
	}

	buf.Reset()
	Warn("warn message", "key", "value")
	if !strings.Contains(buf.String(), "warn message") {
		t.Error("expected warn message in output")
	}
}

// TestAuditIncludesUser tests that Audit automatically includes the user.
func TestAuditIncludesUser(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})

	prev := auditLogger
	auditLogger = slog.New(handler)
	t.Cleanup(func() { auditLogger = prev })

	Audit("test action", "action", "test.action")

	output := buf.String()
	if !strings.Contains(output, "user=") {
		t.Errorf("expected 'user=' in audit output, got: %s", output)
	}
}

// TestSyslogHandlerEnabled tests the syslog handler's Enabled method.
func TestSyslogHandlerEnabled(t *testing.T) {
	// Create a handler (may be nil on non-Unix systems)
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
