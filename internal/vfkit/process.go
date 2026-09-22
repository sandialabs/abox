//go:build darwin

package vfkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/childproc"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/procutil"
)

// procName is the vfkit binary/comm name: the command to exec, the label the
// supervisor logs under, and the substring that identifies a vfkit process.
const procName = "vfkit"

// StartVM launches vfkit as a detached background process.
// The process is placed in its own process group so it survives the parent
// exiting. The PID is written to cfg.PIDFile for later reconnection.
//
// vfkit attaches its virtio-net device to cfg.NetSocketPath, the unix datagram
// socket a vmnet-helper process (launched in --socket mode) is serving; vfkit
// creates its own local socket and connects. No file descriptor is inherited,
// so nothing has to survive the sudo boundary.
//
// Returns the PID of the launched process.
func StartVM(cfg VMConfig) (int, error) {
	args := BuildArgs(cfg)

	logging.Debug("starting vfkit",
		"name", cfg.Name,
		"args", strings.Join(args, " "),
	)

	vfkit := exec.Command(procName, args...)

	// Put vfkit in its own process group so it isn't killed when abox exits.
	procutil.Detach(vfkit)

	// Redirect stderr to log file if configured.
	var logFile *os.File
	if cfg.LogFile != "" {
		var err error
		logFile, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 0, fmt.Errorf("open vfkit log file: %w", err)
		}
		vfkit.Stderr = logFile
		vfkit.Stdout = logFile
	}

	if err := vfkit.Start(); err != nil {
		// Close the log file if we opened one — the child never launched,
		// so nobody else will close it.
		if logFile != nil {
			_ = logFile.Close()
		}
		return 0, fmt.Errorf("start vfkit: %w", err)
	}
	// On success, logFile stays open — the child process inherited the fd,
	// and the OS closes it when vfkit exits.

	pid := vfkit.Process.Pid

	// Write PID file for later reconnection.
	if cfg.PIDFile != "" {
		if err := os.WriteFile(cfg.PIDFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			// Kill the process if we can't write the PID file — we'd lose track of it.
			// Reap it too so it doesn't linger as a zombie; the Kill above means
			// Wait won't block. Close the log file too since the child is gone.
			_ = vfkit.Process.Kill()
			_, _ = vfkit.Process.Wait()
			if logFile != nil {
				_ = logFile.Close()
			}
			return 0, fmt.Errorf("write vfkit PID file: %w", err)
		}
	}

	logging.Debug("vfkit started", "name", cfg.Name, "pid", pid)

	// Release the process so we don't hold a reference — it's now orphaned
	// to launchd (PID 1) which will reap it when it exits.
	_ = vfkit.Process.Release()

	return pid, nil
}

// VerifyLive confirms a freshly launched vfkit is actually running rather than
// having died instantly (finding F13). exec.Start() returning success only means
// the fork happened; a taken REST port, corrupt disk, or EFI store error can
// kill vfkit microseconds later. VerifyLive polls until either the REST API
// answers (definitive: the process is up and serving) or the grace window
// elapses, and fails fast if the process disappears in the meantime.
//
// If restfulURI is empty (no REST API configured) it can only check that the
// process stayed alive for the duration of the window.
func VerifyLive(pidFile, restfulURI string, grace time.Duration) error {
	deadline := time.Now().Add(grace)
	for {
		if !IsRunning(pidFile) {
			return errors.New("vfkit process exited immediately after launch")
		}
		if restfulURI != "" {
			if _, err := VMState(restfulURI); err == nil {
				// REST answered: vfkit is up and its lifecycle API works.
				return nil
			}
		}
		if time.Now().After(deadline) {
			// Process is still alive at the deadline. With a REST URI configured
			// we never got a clean answer, but a live process that simply hasn't
			// finished bringing up its API yet is the common case — treat the
			// surviving process as success rather than tearing down a healthy VM.
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// LogTail returns up to the last n lines of the named file, for surfacing in
// error messages when a launch fails. Returns "" if the file can't be read or
// is empty; callers treat an empty tail as "nothing to show".
func LogTail(path string, n int) string {
	if path == "" || n <= 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return ""
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// StopVM sends SIGTERM to the vfkit process, waits up to 5 seconds for it to
// exit, then sends SIGKILL if it's still alive. Cleans up the PID file.
func StopVM(pidFile string) error {
	return supervisor.Stop(pidFile)
}

// WaitForExit polls the vfkit PID file until the referenced process is no
// longer running, the timeout elapses, or ctx is cancelled. It does NOT
// signal the process — callers use it after requesting a graceful (REST/ACPI)
// shutdown to wait for vfkit to exit on its own.
//
// Returns true if the process exited within the window, false if the timeout
// elapsed. A cancelled ctx returns (false, ctx.Err()). A missing/stale PID file
// counts as exited (true, nil).
func WaitForExit(ctx context.Context, pidFile string, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		if !IsRunning(pidFile) {
			// Process gone — clean up any stale PID file it left behind.
			_ = os.Remove(pidFile)
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ForceStopVM sends SIGKILL to the vfkit process immediately.
func ForceStopVM(pidFile string) error {
	return supervisor.ForceStop(pidFile)
}

// IsRunning reads the PID file and checks if the vfkit process is alive.
// Returns false if the PID file is missing, stale, or the process is dead.
func IsRunning(pidFile string) bool {
	return supervisor.IsRunning(pidFile)
}

// ReadPID reads and validates a PID from a PID file.
func ReadPID(pidFile string) (int, error) {
	return supervisor.ReadPID(pidFile)
}

// CleanupPIDFile removes a PID file if the process it references is no longer running.
func CleanupPIDFile(pidFile string) error {
	return supervisor.CleanupPIDFile(pidFile)
}

// supervisor owns the shared PID-file/comm-verification lifecycle. isVfkitProcess
// is the comm guard that keeps StopVM/ForceStopVM from signalling a reused PID.
var supervisor = childproc.Supervisor{Name: procName, Matches: isVfkitProcess}

// lookupComm returns the command name (comm) of a PID. It is a package
// variable so tests can substitute a deterministic implementation without
// shelling out to ps or depending on what processes happen to be running.
// It defaults to the real ps-based lookup.
var lookupComm = childproc.LookupComm

// isVfkitProcess checks that a PID belongs to a vfkit process.
func isVfkitProcess(pid int) bool {
	comm, err := lookupComm(pid)
	if err != nil {
		return false
	}
	return strings.Contains(comm, procName)
}
