//go:build darwin

package vfkit

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

// StartVM launches vfkit as a detached background process.
// The process is placed in its own process group so it survives the parent
// exiting. The PID is written to cfg.PIDFile for later reconnection.
//
// netFD is the parent's handle to one end of a syscall.Socketpair; the
// other end is held by a vmnet-helper process providing NAT/DHCP.
// StartVM attaches netFD to cmd.ExtraFiles so the vfkit child sees it at
// fd NetFDChild, and closes the parent-side copy once vfkit has launched
// (success or failure). Callers must not reuse netFD after StartVM returns.
//
// Returns the PID of the launched process.
func StartVM(cfg VMConfig, netFD *os.File) (int, error) {
	if netFD == nil {
		return 0, fmt.Errorf("vfkit: netFD is required (socketpair end for vmnet-helper)")
	}
	if cfg.NetFD != NetFDChild {
		// Close so the fd isn't leaked on the error return.
		_ = netFD.Close()
		return 0, fmt.Errorf(
			"vfkit: cfg.NetFD must be %d (cmd.ExtraFiles[0] maps to fd %d in the child), got %d",
			NetFDChild, NetFDChild, cfg.NetFD,
		)
	}

	args := BuildArgs(cfg)

	logging.Debug("starting vfkit",
		"name", cfg.Name,
		"args", strings.Join(args, " "),
	)

	vfkit := exec.Command("vfkit", args...)

	// Put vfkit in its own process group so it isn't killed when abox exits.
	vfkit.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Hand the socketpair end to the child. ExtraFiles[0] maps to fd 3.
	vfkit.ExtraFiles = []*os.File{netFD}

	// Redirect stderr to log file if configured.
	var logFile *os.File
	if cfg.LogFile != "" {
		var err error
		logFile, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			// Nothing has launched yet; close the caller's fd so they aren't
			// left holding it, then return.
			_ = netFD.Close()
			return 0, fmt.Errorf("open vfkit log file: %w", err)
		}
		vfkit.Stderr = logFile
		vfkit.Stdout = logFile
	}

	if err := vfkit.Start(); err != nil {
		// Close the log file if we opened one — the child never launched,
		// so nobody else will close it. Same for the net fd.
		if logFile != nil {
			_ = logFile.Close()
		}
		_ = netFD.Close()
		return 0, fmt.Errorf("start vfkit: %w", err)
	}
	// On success, logFile stays open — the child process inherited the fd,
	// and the OS closes it when vfkit exits. Close the parent's copy of the
	// net fd now; the child holds the other half of the socketpair.
	_ = netFD.Close()

	pid := vfkit.Process.Pid

	// Write PID file for later reconnection.
	if cfg.PIDFile != "" {
		if err := os.WriteFile(cfg.PIDFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			// Kill the process if we can't write the PID file — we'd lose track of it.
			_ = vfkit.Process.Kill()
			return 0, fmt.Errorf("write vfkit PID file: %w", err)
		}
	}

	logging.Debug("vfkit started", "name", cfg.Name, "pid", pid)

	// Release the process so we don't hold a reference — it's now orphaned
	// to launchd (PID 1) which will reap it when it exits.
	_ = vfkit.Process.Release()

	return pid, nil
}

// StopVM sends SIGTERM to the vfkit process, waits up to 5 seconds for it to
// exit, then sends SIGKILL if it's still alive. Cleans up the PID file.
func StopVM(pidFile string) error {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return err
	}

	if !isVfkitProcess(pid) {
		logging.Warn("PID is not a vfkit process, cleaning up stale PID file", "pid", pid)
		_ = os.Remove(pidFile)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find vfkit process %d: %w", pid, err)
	}

	logging.Debug("sending SIGTERM to vfkit", "pid", pid)
	if sigErr := proc.Signal(syscall.SIGTERM); sigErr != nil {
		// Process already gone — clean up.
		logging.Debug("vfkit process already exited", "pid", pid, "error", sigErr)
		_ = os.Remove(pidFile)
		return nil
	}

	// Poll for exit (up to 5 seconds).
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if !processAlive(proc) {
			_ = os.Remove(pidFile)
			return nil
		}
	}

	// Still alive — force kill.
	logging.Warn("vfkit did not stop gracefully, sending SIGKILL", "pid", pid)
	if err := proc.Kill(); err != nil {
		logging.Warn("failed to SIGKILL vfkit", "pid", pid, "error", err)
	}

	_ = os.Remove(pidFile)
	return nil
}

// ForceStopVM sends SIGKILL to the vfkit process immediately.
func ForceStopVM(pidFile string) error {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return err
	}

	if !isVfkitProcess(pid) {
		logging.Warn("PID is not a vfkit process, cleaning up stale PID file", "pid", pid)
		_ = os.Remove(pidFile)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find vfkit process %d: %w", pid, err)
	}

	logging.Debug("sending SIGKILL to vfkit", "pid", pid)
	if err := proc.Kill(); err != nil {
		logging.Warn("failed to SIGKILL vfkit", "pid", pid, "error", err)
	}

	_ = os.Remove(pidFile)
	return nil
}

// IsRunning reads the PID file and checks if the vfkit process is alive.
// Returns false if the PID file is missing, stale, or the process is dead.
func IsRunning(pidFile string) bool {
	pid, err := ReadPID(pidFile)
	if err != nil {
		return false
	}

	if !isVfkitProcess(pid) {
		return false
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Signal 0 checks existence without actually sending a signal.
	return proc.Signal(syscall.Signal(0)) == nil
}

// ReadPID reads and validates a PID from a PID file.
func ReadPID(pidFile string) (int, error) {
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

// CleanupPIDFile removes a PID file if the process it references is no longer running.
func CleanupPIDFile(pidFile string) error {
	if IsRunning(pidFile) {
		return fmt.Errorf("vfkit process is still running (PID file: %s)", pidFile)
	}
	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale PID file %s: %w", pidFile, err)
	}
	return nil
}

// processAlive checks if a process is still running via signal 0.
func processAlive(proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

// isVfkitProcess checks that a PID belongs to a vfkit process.
// On macOS, /proc doesn't exist, so we use the ps command.
func isVfkitProcess(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(out))
	return strings.Contains(comm, "vfkit")
}
