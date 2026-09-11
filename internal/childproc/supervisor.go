//go:build unix

// Package childproc provides a small supervisor for detached child processes
// that are tracked by a PID file and identified by their command name (comm).
//
// It is shared by backends that launch long-lived helpers outside abox's own
// process tree (currently the darwin vfkit + vmnet-helper pair). The supervisor
// routes liveness and graceful termination through the internal/procutil seam so
// callers depend on the capability rather than a platform-specific syscall.
//
// The build tag is `unix` (darwin is a subset) because comm resolution shells
// out to `ps`, which has no Windows equivalent. procutil itself stays a thin
// syscall seam; this package layers the PID-file/comm-verification policy and
// logging on top of it.
package childproc

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/procutil"
)

// stopPollCount and stopPollInterval define the SIGTERM→SIGKILL escalation
// window: after SIGTERM the supervisor polls for exit stopPollCount times at
// stopPollInterval each (50 × 100ms = 5s) before forcing a SIGKILL. They are
// vars (not consts) only so tests can shrink the window; production never
// mutates them.
var (
	stopPollCount    = 50
	stopPollInterval = 100 * time.Millisecond
)

// Supervisor manages a single kind of detached child process tracked by a PID
// file. Name is used only in log/error messages ("vfkit", "vmnet-helper").
// Matches is the comm-verification guard: it reports whether a PID is actually
// one of ours. Every operation that would signal a PID first consults Matches,
// so a stale PID file whose PID has been reused by an unrelated process is
// cleaned up rather than signalled — this is the safety guard that prevents
// killing an innocent process.
type Supervisor struct {
	Name    string
	Matches func(pid int) bool

	// Terminate and Kill optionally override how SIGTERM and SIGKILL are
	// delivered to a tracked PID. When nil (the default) the supervisor signals
	// the PID directly via the procutil syscall seam. Set them when the tracked
	// child may run as a different user than abox — e.g. vmnet-helper spawned via
	// `sudo` on macOS ≤15, where a direct syscall from the unprivileged abox
	// process would fail with EPERM — so termination routes through an escalated
	// path (`sudo -n kill`) instead. Both should return a procutil.IsNotExistErr
	// error (ESRCH) when the target is already gone so Stop can distinguish that
	// from a delivery failure.
	Terminate func(pid int) error
	Kill      func(pid int) error
}

// terminate delivers SIGTERM to pid via the override if set, else procutil.
func (s Supervisor) terminate(pid int) error {
	if s.Terminate != nil {
		return s.Terminate(pid)
	}
	return procutil.TerminatePID(pid)
}

// kill delivers SIGKILL to pid via the override if set, else procutil.
func (s Supervisor) kill(pid int) error {
	if s.Kill != nil {
		return s.Kill(pid)
	}
	return procutil.KillPID(pid)
}

// waitGone polls until pid is no longer alive, up to the SIGTERM escalation
// window (stopPollCount × stopPollInterval), returning true once it is gone.
//
// SIGKILL delivery is asynchronous, and a child we do not parent (e.g. vfkit,
// which is Release()'d and reparented to launchd) lingers as a dying/zombie entry
// — for which kill(pid,0) still succeeds — until its new parent reaps it. Checking
// liveness in the same instant we SIGKILL therefore races the reap and can report
// a just-killed process as still alive. Polling briefly closes that window while
// still returning false for a genuinely unkillable process (e.g. a root-owned
// helper), which keeps the fail-closed behavior callers rely on.
func (s Supervisor) waitGone(pid int) bool {
	if !procutil.IsAlive(pid) {
		return true
	}
	for range stopPollCount {
		time.Sleep(stopPollInterval)
		if !procutil.IsAlive(pid) {
			return true
		}
	}
	return false
}

// ReadPID reads and validates a PID from a PID file.
func (s Supervisor) ReadPID(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, fmt.Errorf("read PID file %s: %w", pidFile, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid PID in %s: %q", pidFile, strings.TrimSpace(string(data)))
	}
	return pid, nil
}

// IsRunning reads the PID file and reports whether the referenced process is
// alive and still matches (i.e. is one of ours). Returns false if the PID file
// is missing, stale, the PID has been reused by an unrelated process, or the
// process is dead.
func (s Supervisor) IsRunning(pidFile string) bool {
	pid, err := s.ReadPID(pidFile)
	if err != nil {
		return false
	}
	if !s.Matches(pid) {
		return false
	}
	return procutil.IsAlive(pid)
}

// CleanupPIDFile removes a PID file if the process it references is no longer
// running. It refuses (returns an error) while the process is still alive.
func (s Supervisor) CleanupPIDFile(pidFile string) error {
	if s.IsRunning(pidFile) {
		return fmt.Errorf("%s process is still running (PID file: %s)", s.Name, pidFile)
	}
	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale PID file %s: %w", pidFile, err)
	}
	return nil
}

// Stop sends SIGTERM to the process from pidFile, waits up to 5 seconds for it
// to exit (polling at 100ms), then sends SIGKILL if it's still alive. The PID
// file is removed on every non-error return. A PID that no longer matches is
// treated as a stale PID file and simply cleaned up without signalling.
func (s Supervisor) Stop(pidFile string) error {
	pid, err := s.ReadPID(pidFile)
	if err != nil {
		return err
	}

	if !s.Matches(pid) {
		logging.Warn("PID is not a "+s.Name+" process, cleaning up stale PID file", "pid", pid)
		_ = os.Remove(pidFile)
		return nil
	}

	logging.Debug("sending SIGTERM to "+s.Name, "pid", pid)
	if sigErr := s.terminate(pid); sigErr != nil {
		if procutil.IsNotExistErr(sigErr) {
			// Process already gone — clean up.
			logging.Debug(s.Name+" process already exited", "pid", pid)
			_ = os.Remove(pidFile)
			return nil
		}
		// Could not deliver the signal (e.g. a root-owned helper we lack
		// permission to signal directly, or an escalation failure). Do NOT assume
		// the process is gone — fall through and verify liveness before deciding.
		logging.Warn("failed to signal "+s.Name+", verifying liveness", "pid", pid, "error", sigErr)
	}

	// Poll for exit (up to 5 seconds).
	for range stopPollCount {
		time.Sleep(stopPollInterval)
		if !procutil.IsAlive(pid) {
			_ = os.Remove(pidFile)
			return nil
		}
	}

	// Still alive after the grace period. Re-verify identity before force-killing:
	// during the poll window our process may have exited and the OS may have
	// reused its PID for an unrelated (possibly privileged) process. If the PID no
	// longer matches, the original process is gone — treat it as a stale PID file
	// and clean up rather than SIGKILL an innocent process.
	if !s.Matches(pid) {
		logging.Warn("PID no longer a "+s.Name+" process after SIGTERM (likely exited and PID reused); not sending SIGKILL", "pid", pid)
		_ = os.Remove(pidFile)
		return nil
	}

	// Still alive — force kill.
	logging.Warn(s.Name+" did not stop gracefully, sending SIGKILL", "pid", pid)
	if killErr := s.kill(pid); killErr != nil {
		logging.Warn("failed to SIGKILL "+s.Name, "pid", pid, "error", killErr)
	}

	// Verify before dropping the PID file: if the process could not actually be
	// killed (e.g. a root-owned helper on macOS ≤15), keep the PID file so a later
	// reclaim can find and retry it rather than silently orphaning the process.
	// Poll briefly so an asynchronous SIGKILL reap isn't mistaken for a survivor.
	if !s.waitGone(pid) {
		return fmt.Errorf("%s (pid %d) could not be stopped", s.Name, pid)
	}
	_ = os.Remove(pidFile)
	return nil
}

// ForceStop sends SIGKILL to the process immediately and removes the PID file.
// A PID that no longer matches is treated as a stale PID file and cleaned up
// without signalling.
func (s Supervisor) ForceStop(pidFile string) error {
	pid, err := s.ReadPID(pidFile)
	if err != nil {
		return err
	}

	if !s.Matches(pid) {
		logging.Warn("PID is not a "+s.Name+" process, cleaning up stale PID file", "pid", pid)
		_ = os.Remove(pidFile)
		return nil
	}

	logging.Debug("sending SIGKILL to "+s.Name, "pid", pid)
	if err := s.kill(pid); err != nil && !procutil.IsNotExistErr(err) {
		logging.Warn("failed to SIGKILL "+s.Name, "pid", pid, "error", err)
	}

	// Keep the PID file if the process survived the kill (e.g. a root-owned helper
	// we cannot signal) so a later reclaim can find it instead of orphaning it.
	// Poll briefly first: SIGKILL is asynchronous and a detached child we don't
	// parent (vfkit → launchd) lingers as a zombie until reaped, so an immediate
	// check would spuriously report it as un-force-stoppable.
	if !s.waitGone(pid) {
		return fmt.Errorf("%s (pid %d) could not be force-stopped", s.Name, pid)
	}
	_ = os.Remove(pidFile)
	return nil
}

// LookupComm returns the command name (comm) of a PID via
// `ps -p <pid> -o comm=`. On macOS /proc does not exist, so ps is how a process
// is identified by name. Packages typically wrap this in a swappable
// package-level variable so tests can inject a deterministic implementation.
func LookupComm(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// LookupCmdline returns the full command line (argv) of a PID via
// `ps -p <pid> -o command=`. Unlike LookupComm (which returns only the executable
// name), this exposes the arguments, letting a caller distinguish e.g. a generic
// `sudo` from `sudo -n vmnet-helper …`. Packages typically wrap this in a
// swappable package-level variable so tests can inject a deterministic result.
func LookupCmdline(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
