//go:build darwin

package vmnethelper

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func withLookupComm(t *testing.T, fn func(pid int) (string, error)) {
	t.Helper()
	prev := lookupComm
	lookupComm = fn
	t.Cleanup(func() { lookupComm = prev })
}

func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run helper process: %v", err)
	}
	return cmd.Process.Pid
}

func writePIDFile(t *testing.T, pid int) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.pid")
	if err := os.WriteFile(f, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// ---------- isHelperProcess ----------

func TestIsHelperProcess_VmnetHelper(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "/opt/homebrew/libexec/vmnet-helper", nil })
	if !isHelperProcess(1) {
		t.Error("should match a comm containing vmnet-helper")
	}
}

func TestIsHelperProcess_Sudo(t *testing.T) {
	// On macOS 15 the recorded PID is sudo's; both bare 'sudo' and '/usr/bin/sudo'
	// must be recognised so we still manage the child via its sudo parent.
	withLookupComm(t, func(int) (string, error) { return "sudo", nil })
	if !isHelperProcess(1) {
		t.Error("should match bare 'sudo'")
	}
	withLookupComm(t, func(int) (string, error) { return "/usr/bin/sudo", nil })
	if !isHelperProcess(1) {
		t.Error("should match '/usr/bin/sudo'")
	}
}

func TestIsHelperProcess_WrongProcess(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "bash", nil })
	if isHelperProcess(os.Getpid()) {
		t.Error("must not match an unrelated process comm")
	}
}

func TestIsHelperProcess_LookupError(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "", os.ErrNotExist })
	if isHelperProcess(999999) {
		t.Error("must be false when comm lookup fails")
	}
}

// ---------- Stop / ForceStop stale-PID handling ----------

func TestStop_StalePIDFileRemovedNotKilled(t *testing.T) {
	// PID file points at our own live PID but comm isn't a helper. Stop must
	// remove the stale file and NOT signal the wrong process.
	withLookupComm(t, func(int) (string, error) { return "not-a-helper", nil })
	f := writePIDFile(t, os.Getpid())

	if err := Stop(f); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("Stop should remove the stale PID file, stat err = %v", err)
	}
	// Still alive → the wrong process was not killed.
}

func TestForceStop_StalePIDFileRemovedNotKilled(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "not-a-helper", nil })
	f := writePIDFile(t, os.Getpid())

	if err := ForceStop(f); err != nil {
		t.Fatalf("ForceStop() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("ForceStop should remove the stale PID file, stat err = %v", err)
	}
}

func TestStop_MissingPIDFile(t *testing.T) {
	if err := Stop(filepath.Join(t.TempDir(), "nope.pid")); err == nil {
		t.Error("Stop should error on a missing PID file")
	}
}

// ---------- IsRunning / CleanupPIDFile ----------

func TestIsRunning_WrongProcess(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "bash", nil })
	f := writePIDFile(t, os.Getpid())
	if IsRunning(f) {
		t.Error("IsRunning must be false when the live PID is not a helper")
	}
}

func TestCleanupPIDFile_RemovesStale(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "", os.ErrNotExist })
	f := writePIDFile(t, deadPID(t))
	if err := CleanupPIDFile(f); err != nil {
		t.Fatalf("CleanupPIDFile() error: %v", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("CleanupPIDFile should remove a stale PID file, stat err = %v", err)
	}
}

func TestCleanupPIDFile_RefusesRunning(t *testing.T) {
	withLookupComm(t, func(int) (string, error) { return "vmnet-helper", nil })
	f := writePIDFile(t, os.Getpid())
	if err := CleanupPIDFile(f); err == nil {
		t.Error("CleanupPIDFile should refuse to remove a PID file for a running helper")
	}
}

// ---------- killChild ----------

func TestKillChild_NilSafe(t *testing.T) {
	// Must not panic on a nil cmd or a cmd with no Process.
	killChild(nil)
	killChild(&exec.Cmd{})
}

func TestKillChild_KillsLiveProcess(t *testing.T) {
	// Spawn a sleep we own, then ensure killChild terminates it. killChild
	// calls Release(), which detaches Go's handle, so we reap the child
	// directly with Wait4 and confirm it died from SIGKILL.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid

	killChild(cmd)

	var ws syscall.WaitStatus
	deadline := time.Now().Add(3 * time.Second)
	for {
		wpid, err := syscall.Wait4(pid, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if wpid == pid {
			break
		}
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("reaping killed child failed: wpid=%d err=%v", wpid, err)
		}
	}
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Errorf("child exit status = %v, want killed by SIGKILL", ws)
	}
}

// ---------- readLineWithDeadline ----------

func TestReadLineWithDeadline_Timeout(t *testing.T) {
	// A pipe that is never written to must cause the read to time out rather
	// than block forever (the guard against vmnet-helper hanging at startup).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	start := time.Now()
	_, err = readLineWithDeadline(r, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error when nothing is written")
	}
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Errorf("returned too early (%v); deadline not honored", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("returned too late (%v); should be near the 200ms deadline", elapsed)
	}
}

func TestReadLineWithDeadline_ReadsLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	go func() {
		_, _ = w.WriteString("hello world\nsecond line\n")
		_ = w.Close()
	}()

	line, err := readLineWithDeadline(r, 2*time.Second)
	if err != nil {
		t.Fatalf("readLineWithDeadline() error: %v", err)
	}
	if string(line) != "hello world" {
		t.Errorf("got %q, want first line only", string(line))
	}
}

func TestReadLineWithDeadline_EOFNoData(t *testing.T) {
	// Writer closes without writing → EOF before any line → error.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	_ = w.Close()

	if _, err := readLineWithDeadline(r, 2*time.Second); err == nil {
		t.Error("expected error when stdout closes before any line is emitted")
	}
}
