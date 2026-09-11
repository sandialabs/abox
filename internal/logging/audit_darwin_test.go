//go:build darwin

package logging

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeLogger points newLoggerCmd at /bin/cat with stdout redirected to path, so a
// test captures exactly what the handler writes to the child's stdin (mirrors the
// qemuimg.runCmd seam). Returns a restore func.
func fakeLogger(t *testing.T, path string) func() {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open capture file: %v", err)
	}
	prev := newLoggerCmd
	newLoggerCmd = func() *exec.Cmd {
		c := exec.Command("/bin/cat")
		c.Stdout = f
		return c
	}
	return func() {
		newLoggerCmd = prev
		_ = f.Close()
	}
}

// TestLoggerAuditHandlerWritesEvent verifies an audit event written through the
// handler reaches the logger child's stdin as one sentinel-prefixed key=value line.
func TestLoggerAuditHandlerWritesEvent(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "capture.log")
	closeAuditSink() // drop any pipe a prior test/init left open
	restore := fakeLogger(t, capture)
	defer restore()

	handler := newAuditHandler()
	if handler == nil {
		t.Fatal("newAuditHandler returned nil")
	}

	slog.New(handler).Info("instance.start", "instance", "dev", "user", "alice")
	closeAuditSink() // drain: close stdin, cat sees EOF and exits before we read

	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	line := string(data)
	for _, want := range []string{"abox ", "level=INFO", "msg=instance.start", "instance=dev", "user=alice"} {
		if !strings.Contains(line, want) {
			t.Errorf("captured audit line missing %q; got: %s", want, line)
		}
	}
	if !strings.HasPrefix(line, "abox ") {
		t.Errorf("audit line must start with the abox sentinel; got: %s", line)
	}
}

// TestLoggerAuditHandlerClonesShareOnePipe verifies WithAttrs/WithGroup clones
// reuse the single logger child rather than spawning one each.
func TestLoggerAuditHandlerClonesShareOnePipe(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "capture.log")
	closeAuditSink()
	restore := fakeLogger(t, capture)
	defer restore()
	defer closeAuditSink()

	h, ok := newAuditHandler().(*loggerAuditHandler)
	if !ok {
		t.Fatal("expected *loggerAuditHandler")
	}
	withAttrs, ok := h.WithAttrs([]slog.Attr{slog.String("k", "v")}).(*loggerAuditHandler)
	if !ok {
		t.Fatal("expected *loggerAuditHandler from WithAttrs")
	}
	withGroup, ok := h.WithGroup("g").(*loggerAuditHandler)
	if !ok {
		t.Fatal("expected *loggerAuditHandler from WithGroup")
	}
	if withAttrs.pipe != h.pipe || withGroup.pipe != h.pipe {
		t.Error("handler clones must share the same *loggerPipe (no extra logger child)")
	}
}

// TestAuditSinkReinitCycle exercises the init/close reopen cycle with concurrent
// writes so `go test -race` catches any hazard between Handle and closeAuditSink.
func TestAuditSinkReinitCycle(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "capture.log")
	closeAuditSink()
	restore := fakeLogger(t, capture)
	defer restore()
	defer closeAuditSink()

	for range 3 {
		h := newAuditHandler()
		newAuditHandler() // idempotent: init→init must not double-spawn
		if h == nil {
			t.Fatal("newAuditHandler returned nil")
		}
		logger := slog.New(h)

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				logger.Info("instance.start", "instance", "dev")
			})
		}
		closeAuditSink() // close concurrent with in-flight writes
		wg.Wait()
	}
}

// TestAuditLogHintUsesLogShow verifies the macOS hint points at the unified log,
// not a file or journalctl.
func TestAuditLogHintUsesLogShow(t *testing.T) {
	hint := AuditLogHint()
	for _, want := range []string{"log show", "BEGINSWITH", "abox"} {
		if !strings.Contains(hint, want) {
			t.Errorf("AuditLogHint should mention %q; got %q", want, hint)
		}
	}
	for _, bad := range []string{"journalctl", "audit.log"} {
		if strings.Contains(hint, bad) {
			t.Errorf("AuditLogHint should not mention %q; got %q", bad, hint)
		}
	}
}
