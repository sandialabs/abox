//go:build darwin

package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/logutil"
)

// newFileAuditHandlerAt is a test helper that opens a fileAuditHandler at the
// given path without using the package-level singleton.
func newFileAuditHandlerAt(path string) (*fileAuditHandler, error) {
	w, err := logutil.NewRotateWriter(path, logutil.DefaultRotateConfig())
	if err != nil {
		return nil, err
	}
	return &fileAuditHandler{writer: w}, nil
}

// resetAuditSingleton resets the package-level audit singleton so tests can
// call newAuditHandler repeatedly with different environments.
func resetAuditSingleton() {
	auditFileWriterOnce = sync.Once{}
	auditFileWriter = nil
	auditFilePath = ""
}

// TestFileAuditHandlerWritesEvent verifies that an audit event written through
// fileAuditHandler appears in the file.
func TestFileAuditHandlerWritesEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	handler, err := newFileAuditHandlerAt(logPath)
	if err != nil {
		t.Fatalf("newFileAuditHandlerAt: %v", err)
	}
	t.Cleanup(func() { _ = handler.writer.Close() })

	logger := slog.New(handler)
	logger.Info("instance.start", "instance", "dev", "user", "alice")

	if err := handler.writer.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	line := string(data)
	for _, want := range []string{"instance.start", "instance=dev", "user=alice"} {
		if !strings.Contains(line, want) {
			t.Errorf("audit log line missing %q; got: %s", want, line)
		}
	}
}

// TestFileAuditHandlerTimestamp verifies that the log line contains a valid RFC3339 timestamp.
func TestFileAuditHandlerTimestamp(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	handler, err := newFileAuditHandlerAt(logPath)
	if err != nil {
		t.Fatalf("newFileAuditHandlerAt: %v", err)
	}
	t.Cleanup(func() { _ = handler.writer.Close() })

	before := time.Now().UTC().Truncate(time.Second)
	logger := slog.New(handler)
	logger.Info("test.event")

	if err := handler.writer.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	line := strings.TrimSpace(string(data))
	if len(line) < 20 {
		t.Fatalf("log line too short: %q", line)
	}

	// First field is the timestamp.
	ts, err := time.Parse(time.RFC3339, strings.Fields(line)[0])
	if err != nil {
		t.Errorf("first field is not RFC3339: %q; err=%v", strings.Fields(line)[0], err)
		return
	}
	if ts.Before(before) {
		t.Errorf("timestamp %v is before test start %v", ts, before)
	}
}

// TestFileAuditHandlerDebugDropped verifies that DEBUG events are not written.
func TestFileAuditHandlerDebugDropped(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	handler, err := newFileAuditHandlerAt(logPath)
	if err != nil {
		t.Fatalf("newFileAuditHandlerAt: %v", err)
	}
	t.Cleanup(func() { _ = handler.writer.Close() })

	logger := slog.New(handler)
	logger.Debug("should.not.appear")

	if err := handler.writer.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty audit log for debug event; got: %s", data)
	}
}

// TestNewAuditHandlerDarwin verifies that newAuditHandler returns a non-nil handler
// when XDG_DATA_HOME is set to a writable temp directory.
func TestNewAuditHandlerDarwin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)

	resetAuditSingleton()
	t.Cleanup(resetAuditSingleton)

	h := newAuditHandler()
	if h == nil {
		t.Fatal("expected non-nil handler from newAuditHandler on darwin")
	}
	closeAuditSink()

	// Verify the log file was created.
	expectedPath := filepath.Join(dir, "abox", "logs", "audit.log")
	if _, err := os.Stat(expectedPath); err != nil {
		t.Errorf("audit log file not created at %s: %v", expectedPath, err)
	}
}

// TestAuditLogHintDarwin verifies that AuditLogHint returns a path containing "audit.log".
func TestAuditLogHintDarwin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)

	resetAuditSingleton()
	t.Cleanup(resetAuditSingleton)

	_ = newAuditHandler()
	closeAuditSink()

	hint := AuditLogHint()
	if hint == "" {
		t.Error("AuditLogHint returned empty string")
	}
	if !strings.Contains(hint, "audit.log") {
		t.Errorf("AuditLogHint does not mention audit.log: %q", hint)
	}
}
