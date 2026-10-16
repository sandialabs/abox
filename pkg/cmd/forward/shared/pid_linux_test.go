//go:build linux

package shared

import (
	"os/exec"
	"testing"
	"time"
)

// TestFindPIDByPattern_RequiresAllPatterns exercises the /proc scan against a
// real process: a match requires every pattern in the cmdline, so a process
// carrying the forward spec but a different ssh target is not found.
func TestFindPIDByPattern_RequiresAllPatterns(t *testing.T) {
	const (
		spec   = "localhost:19999:localhost:80"
		target = "e2etestuser@192.0.2.1"
	)

	// Plant spec and target in a long-lived process's argv ($0/$1/$2 of sh -c).
	// The compound command keeps sh from exec-optimizing itself away into bare
	// `sleep` (which would drop the extra argv from /proc/<pid>/cmdline).
	cmd := exec.Command("/bin/sh", "-c", "sleep 30; exit 0", "sh", spec, target)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start helper process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Poll (via WaitForSSHProcess, the production discovery path) until the
	// child has exec'd and its cmdline is visible.
	pid, err := WaitForSSHProcess(5*time.Second, spec, target)
	if err != nil {
		t.Fatalf("expected to find helper process by spec+target: %v", err)
	}
	if pid != cmd.Process.Pid {
		t.Errorf("found pid %d, want %d", pid, cmd.Process.Pid)
	}

	// Same spec, wrong target: must not match.
	if pid, err := FindPIDByPattern(spec, "other@198.51.100.9"); err == nil {
		t.Errorf("spec with wrong target matched pid %d; want no match", pid)
	}
}
