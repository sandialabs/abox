//go:build linux

package start

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/procutil"
)

// TestHelperProcess is a no-op unless invoked as a helper subprocess (the
// standard os/exec test pattern). When ABOX_WANT_HELPER=1 it sleeps so the
// parent can treat it as a live "abox process" — its /proc/<pid>/exe resolves to
// this test binary, which is what daemon.IsAboxProcess compares against.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("ABOX_WANT_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func writePID(t *testing.T, path string, pid int) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
}

// Live PID + present socket => "already running" (true), nothing removed.
func TestCheckAlreadyRunning_LivePIDWithSocket(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "dns.pid")
	socket := filepath.Join(dir, "dns.sock")

	// Our own PID is a live "abox process": /proc/self/exe == os.Executable().
	writePID(t, pidFile, os.Getpid())
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatalf("create socket file: %v", err)
	}

	var buf bytes.Buffer
	if got := checkAlreadyRunning(&buf, "dns", pidFile, socket); !got {
		t.Fatalf("expected true (daemon running), got false; output=%q", buf.String())
	}
	if _, err := os.Stat(pidFile); err != nil {
		t.Errorf("pid file should be preserved, got: %v", err)
	}
	if _, err := os.Stat(socket); err != nil {
		t.Errorf("socket should be preserved, got: %v", err)
	}
}

// Live PID but missing socket => kill the stale daemon, remove files, return false.
func TestCheckAlreadyRunning_LivePIDNoSocket(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "dns.pid")
	socket := filepath.Join(dir, "dns.sock") // intentionally not created

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "ABOX_WANT_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	pid := cmd.Process.Pid
	// Reap the child in the background so that, once checkAlreadyRunning kills it,
	// it does not linger as a zombie (a zombie still answers kill(pid,0)).
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	// Best-effort kill if the assertion path leaves it running; the goroutine above
	// reaps it in all cases (waitCh is buffered, so it never leaks).
	defer func() { _ = cmd.Process.Kill() }()

	writePID(t, pidFile, pid)

	var buf bytes.Buffer
	if got := checkAlreadyRunning(&buf, "dns", pidFile, socket); got {
		t.Fatalf("expected false (socket missing), got true; output=%q", buf.String())
	}

	// checkAlreadyRunning should have signalled the stale daemon; confirm it exits.
	select {
	case <-waitCh:
		// process reaped — killed as expected
	case <-time.After(3 * time.Second):
		t.Errorf("expected stale daemon (pid %d) to be killed", pid)
	}

	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Errorf("pid file should have been removed, stat err=%v", err)
	}
}

// Dead PID with leftover files => clean up stale files, return false.
func TestCheckAlreadyRunning_DeadPID(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "dns.pid")
	socket := filepath.Join(dir, "dns.sock")

	// Find a PID that is not alive.
	deadPID := 999999
	for procutil.IsAlive(deadPID) {
		deadPID++
	}
	writePID(t, pidFile, deadPID)
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatalf("create socket file: %v", err)
	}

	var buf bytes.Buffer
	if got := checkAlreadyRunning(&buf, "dns", pidFile, socket); got {
		t.Fatalf("expected false (dead pid), got true")
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Errorf("stale pid file should have been removed, stat err=%v", err)
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Errorf("stale socket should have been removed, stat err=%v", err)
	}
}
