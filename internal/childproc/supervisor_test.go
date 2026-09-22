//go:build unix

package childproc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// writePID writes a PID file in a temp dir and returns its path.
func writePID(t *testing.T, pid int) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.pid")
	if err := os.WriteFile(f, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	return f
}

// shrinkPoll shortens the SIGTERM→SIGKILL escalation window so tests that
// exercise the force-kill path don't wait the full 5s.
func shrinkPoll(t *testing.T) {
	t.Helper()
	oc, oi := stopPollCount, stopPollInterval
	stopPollCount, stopPollInterval = 2, time.Millisecond
	t.Cleanup(func() { stopPollCount, stopPollInterval = oc, oi })
}

func TestStop_UsesTerminateOverride_AlreadyGone(t *testing.T) {
	f := writePID(t, 4242)
	called := false
	s := Supervisor{
		Name:    "test",
		Matches: func(int) bool { return true },
		// Report the process as already gone (ESRCH) — Stop must treat that as a
		// clean exit and remove the PID file without polling or killing.
		Terminate: func(int) error { called = true; return syscall.ESRCH },
		Kill:      func(int) error { t.Fatal("Kill must not run when Terminate reports gone"); return nil },
	}
	if err := s.Stop(f); err != nil {
		t.Fatalf("Stop() = %v, want nil", err)
	}
	if !called {
		t.Error("Terminate override was not invoked")
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("PID file should be removed, stat err = %v", err)
	}
}

func TestStop_KeepsPIDFile_WhenUnkillable(t *testing.T) {
	shrinkPoll(t)
	// The current test process is genuinely alive; overrides that never actually
	// signal it simulate a process abox lacks permission to kill (e.g. a
	// root-owned helper on macOS ≤15).
	f := writePID(t, os.Getpid())
	killed := false
	s := Supervisor{
		Name:      "test",
		Matches:   func(int) bool { return true },
		Terminate: func(int) error { return nil }, // "delivered" but process stays up
		Kill:      func(int) error { killed = true; return nil },
	}
	err := s.Stop(f)
	if err == nil {
		t.Fatal("Stop() = nil, want error when the process could not be stopped")
	}
	if !killed {
		t.Error("Kill override was not invoked on escalation")
	}
	if _, statErr := os.Stat(f); statErr != nil {
		t.Errorf("PID file must be kept when the process survives, stat err = %v", statErr)
	}
}

func TestStop_SkipsSIGKILL_WhenPIDRecycledDuringGrace(t *testing.T) {
	shrinkPoll(t)
	// The tracked process is alive at the start (Matches true) but exits during
	// the SIGTERM grace window and its PID is reused by an unrelated process
	// (Matches false on the re-check). Stop must NOT SIGKILL the reused PID; it
	// should treat the PID file as stale and remove it.
	f := writePID(t, os.Getpid()) // genuinely alive, so the poll loop reaches the re-check
	matchCalls := 0
	killed := false
	s := Supervisor{
		Name: "test",
		Matches: func(int) bool {
			matchCalls++
			return matchCalls == 1 // true on the initial guard, false on the pre-SIGKILL re-check
		},
		Terminate: func(int) error { return nil }, // "delivered", process stays up through the poll
		Kill:      func(int) error { killed = true; return nil },
	}
	if err := s.Stop(f); err != nil {
		t.Fatalf("Stop() = %v, want nil (stale PID after recycle)", err)
	}
	if killed {
		t.Error("Kill must not run once the PID no longer matches after the grace window")
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("stale PID file should be removed, stat err = %v", err)
	}
}

func TestForceStop_KeepsPIDFile_WhenUnkillable(t *testing.T) {
	shrinkPoll(t) // the poll-for-exit loop must not wait the full window on a live PID
	f := writePID(t, os.Getpid())
	s := Supervisor{
		Name:    "test",
		Matches: func(int) bool { return true },
		Kill:    func(int) error { return nil }, // no-op: process stays alive
	}
	if err := s.ForceStop(f); err == nil {
		t.Fatal("ForceStop() = nil, want error when the process survives")
	}
	if _, statErr := os.Stat(f); statErr != nil {
		t.Errorf("PID file must be kept when the process survives, stat err = %v", statErr)
	}
}

func TestForceStop_Succeeds_WhenProcessExitsAfterKill(t *testing.T) {
	shrinkPoll(t)
	// A real child that is genuinely alive at the ForceStop call but which the Kill
	// override actually terminates. Exit is asynchronous — the process may still be
	// reapable/alive for an instant after SIGKILL — so ForceStop must poll (waitGone)
	// rather than check liveness once. This reproduces the vfkit reaping race.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := cmd.Process.Pid
	// Reap the child in the background so the killed process leaves the table
	// (mirrors launchd reaping a reparented vfkit).
	go func() { _ = cmd.Wait() }()

	f := writePID(t, pid)
	s := Supervisor{
		Name:    "test",
		Matches: func(int) bool { return true },
		Kill: func(p int) error {
			return syscall.Kill(p, syscall.SIGKILL)
		},
	}
	if err := s.ForceStop(f); err != nil {
		t.Fatalf("ForceStop() = %v, want nil once the process exits after SIGKILL", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("PID file should be removed after a successful force-stop, stat err = %v", err)
	}
}

func TestStop_DefaultsToProcutil_WhenNoOverride(t *testing.T) {
	// No Terminate/Kill override + a non-matching PID: Stop must take the stale
	// path (remove file, no signalling) — verifies the default path still works.
	f := writePID(t, os.Getpid())
	s := Supervisor{Name: "test", Matches: func(int) bool { return false }}
	if err := s.Stop(f); err != nil {
		t.Fatalf("Stop() = %v, want nil", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("stale PID file should be removed, stat err = %v", err)
	}
}
