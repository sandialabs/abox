//go:build unix

package daemon

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/procutil"
)

// startIgnoreTermChild spawns a child that ignores SIGTERM and sleeps, so
// signalFallback's SIGTERM is a no-op and the post-grace liveness check is
// reached. The child prints a readiness line only after the trap is installed;
// we block on it so a SIGTERM racing the child's startup can't hit the default
// (fatal) disposition. The child is reaped in the background and killed on cleanup.
func startIgnoreTermChild(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", `trap "" TERM; echo ready; sleep 30`)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	go func() { _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatalf("waiting for child readiness: %v", err)
	}
	return pid
}

func writeDaemonPID(t *testing.T, pid int) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "daemon.pid")
	if err := os.WriteFile(f, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	return f
}

// TestSignalFallback_SkipsSIGKILL_WhenPIDRecycledDuringGrace verifies the
// re-verify-before-SIGKILL guard: the PID is ours at the SIGTERM gate but no
// longer ours on the post-grace re-check (simulating exit + PID reuse), so no
// SIGKILL is sent and the process survives.
func TestSignalFallback_SkipsSIGKILL_WhenPIDRecycledDuringGrace(t *testing.T) {
	pid := startIgnoreTermChild(t)

	calls := 0
	orig := verifyAboxProcess
	verifyAboxProcess = func(int) bool { calls++; return calls == 1 } // ours at gate, not ours at re-check
	t.Cleanup(func() { verifyAboxProcess = orig })

	signalFallback(writeDaemonPID(t, pid))

	if !procutil.IsAlive(pid) {
		t.Error("process was SIGKILLed despite failing the post-grace identity re-check")
	}
}

// TestSignalFallback_SIGKILLs_WhenStillOurs verifies that when the PID is still
// confirmed ours after the grace window, SIGKILL is delivered and the process
// dies (it ignores SIGTERM, so only the escalation can kill it).
func TestSignalFallback_SIGKILLs_WhenStillOurs(t *testing.T) {
	pid := startIgnoreTermChild(t)

	orig := verifyAboxProcess
	verifyAboxProcess = func(int) bool { return true }
	t.Cleanup(func() { verifyAboxProcess = orig })

	signalFallback(writeDaemonPID(t, pid))

	// SIGKILL is asynchronous; poll briefly for the process to disappear.
	for range 20 {
		if !procutil.IsAlive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("process still alive; expected SIGKILL escalation when PID remained ours")
}
