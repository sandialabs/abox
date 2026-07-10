package start

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/daemon"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

// FilterType represents the type of filter being started.
type FilterType string

const (
	// FilterDNS represents the DNS filter.
	FilterDNS FilterType = "dns"
	// FilterHTTP represents the HTTP filter.
	FilterHTTP FilterType = "http"
)

// FilterPaths contains the paths needed to start a filter.
type FilterPaths struct {
	Socket  string
	Log     string
	PIDFile string
}

// DaemonPaths contains the paths needed to start a daemon.
type DaemonPaths struct {
	Socket  string
	PIDFile string
}

// daemonOptions holds configuration for starting a daemon process.
type daemonOptions struct {
	name       string
	daemonType string
	args       []string
	socketPath string
	pidFile    string
	logFile    *os.File // nil for daemons that manage their own logging
}

// startFilter starts a filter daemon as a background process.
// It validates the log level, creates the log file, spawns the process with
// restrictive umask for socket creation, and waits for the socket to appear.
func startFilter(w io.Writer, name string, filterType FilterType, paths FilterPaths, logLevel string) error {
	running, err := checkAlreadyRunning(w, string(filterType), paths.PIDFile, paths.Socket)
	if err != nil {
		return err
	}
	if running {
		return nil
	}

	// PID file was missing/stale but a matching daemon process may still be
	// orphaned (crash before the PID file was written/cleaned). Reclaim it so we
	// don't spawn a second daemon that dies on "address already in use".
	reclaimOrphanedFilterDaemon(w, name, string(filterType))

	// Validate log level before using it in command args
	if err := validation.ValidateLogLevel(logLevel); err != nil {
		return fmt.Errorf("invalid %s log level: %w", filterType, err)
	}

	// Ensure logs directory exists (parent of log file)
	logDir := filepath.Dir(paths.Log)
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	// Create log file for filter output with restrictive permissions
	logFile, err := os.OpenFile(paths.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}

	// Build command args, including --log-level if configured
	var args []string
	if logLevel != "" {
		args = append(args, "--log-level", logLevel)
	}
	args = append(args, string(filterType), "serve", name)

	opts := daemonOptions{
		name:       name,
		daemonType: string(filterType),
		args:       args,
		socketPath: paths.Socket,
		pidFile:    paths.PIDFile,
		logFile:    logFile,
	}

	return startDaemonProcess(opts)
}

// startDaemon starts a generic daemon as a background process.
// Used for daemons like monitor that don't need log level validation.
func startDaemon(w io.Writer, name string, daemonType string, paths DaemonPaths) error {
	running, err := checkAlreadyRunning(w, daemonType, paths.PIDFile, paths.Socket)
	if err != nil {
		return err
	}
	if running {
		return nil
	}

	reclaimOrphanedFilterDaemon(w, name, daemonType)

	args := []string{daemonType, "serve", name}

	opts := daemonOptions{
		name:       name,
		daemonType: daemonType,
		args:       args,
		socketPath: paths.Socket,
		pidFile:    paths.PIDFile,
		logFile:    nil, // daemon manages its own logging
	}

	return startDaemonProcess(opts)
}

// startDaemonProcess is the common implementation for starting daemon processes.
func startDaemonProcess(opts daemonOptions) error {
	// Get the path to current executable
	exe, err := os.Executable()
	if err != nil {
		if opts.logFile != nil {
			opts.logFile.Close()
		}
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Set restrictive umask before spawning to ensure socket created with proper permissions
	// This prevents a race window where socket could be accessed before chmod
	oldUmask := syscall.Umask(0o077)

	// Spawn daemon as a background process
	cmd := exec.Command(exe, opts.args...)
	cmd.Stdout = opts.logFile
	cmd.Stderr = opts.logFile
	cmd.Dir = "/"

	// Detach from parent process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	startErr := cmd.Start()

	// Restore umask regardless of whether start succeeded
	syscall.Umask(oldUmask)

	if startErr != nil {
		if opts.logFile != nil {
			opts.logFile.Close()
		}
		return fmt.Errorf("failed to start %s daemon: %w", opts.daemonType, startErr)
	}

	pid := cmd.Process.Pid

	// Write PID file for later cleanup with restrictive permissions
	if err := os.WriteFile(opts.pidFile, fmt.Appendf(nil, "%d", pid), 0o600); err != nil {
		logging.Warn("failed to write PID file", "error", err, "daemon", opts.daemonType, "instance", opts.name)
	}

	// Don't wait for the process - let it run in background
	// Close log file handle in parent (child has its own)
	if opts.logFile != nil {
		opts.logFile.Close()
	}

	// Wait briefly for socket to appear, verifying process is still alive
	for range 20 {
		time.Sleep(100 * time.Millisecond)

		// Check if process is still running
		if !isProcessRunning(pid) {
			// The most common immediate-exit cause is a bind failure ("address
			// already in use") when a prior daemon still holds the port. The
			// daemon's own log records the exact error; point the user there
			// instead of leaving them with an opaque message.
			return fmt.Errorf(
				"%s daemon exited immediately after starting (often a port already in "+
					"use by a leftover daemon); see the %s daemon log for the exact error",
				opts.daemonType, opts.daemonType)
		}

		if info, err := os.Stat(opts.socketPath); err == nil {
			return verifySocketPermissions(info, opts.daemonType)
		}
	}

	return fmt.Errorf(
		"%s daemon started but its socket %s never appeared; the daemon may be failing "+
			"to bind its port (check the %s daemon log)",
		opts.daemonType, opts.socketPath, opts.daemonType)
}

// daemonState classifies what the PID file tells us about a daemon.
type daemonState int

const (
	// daemonDead: no PID file, an unparseable PID, or a PID confirmed not
	// running / confirmed not an abox process. Safe to clean up and respawn.
	daemonDead daemonState = iota
	// daemonAlive: the PID file holds a live, confirmed-abox process.
	daemonAlive
	// daemonUnverifiable: a live process holds this PID but we could not confirm
	// whether it is ours (e.g. ps/identity lookup errored). We must NOT delete
	// its socket/PID files or respawn on top of it — doing so is exactly the bug
	// that, on a misbehaving identity check, nukes a healthy daemon's files and
	// spins respawning into "address already in use". Fail loud instead.
	daemonUnverifiable
)

// checkAlreadyRunning reports whether a daemon is already alive based on its
// PID file. If the PID is dead but socket/PID files remain (an ungraceful
// previous exit), it removes the stale files, prints a user-visible recovery
// notice, and returns (false, nil) so the caller can start a fresh daemon. If a
// live process holds the PID but its identity can't be confirmed, it returns an
// error rather than risk deleting a possibly-live daemon's state.
func checkAlreadyRunning(w io.Writer, daemonType, pidFile, socketPath string) (bool, error) {
	if w == nil {
		w = io.Discard
	}
	switch daemonStateOf(pidFile) {
	case daemonAlive:
		logging.Warn("daemon already running", "type", daemonType)
		return true, nil
	case daemonUnverifiable:
		return false, fmt.Errorf(
			"%s daemon PID file points at a running process whose identity could not be "+
				"verified; refusing to delete its state or start a second daemon. "+
				"Stop the existing process or remove %s if it is stale, then retry",
			daemonType, pidFile)
	case daemonDead:
		// Clean up any leftover state from an ungraceful exit, then let the
		// caller start fresh.
		_, socketErr := os.Stat(socketPath)
		_, pidErr := os.Stat(pidFile)
		if socketErr == nil || pidErr == nil {
			fmt.Fprintf(w, "  %s daemon from previous run did not exit cleanly, restarting...\n", daemonType)
			logging.Warn("cleaning up stale daemon files from previous crash", "type", daemonType)
			_ = os.Remove(socketPath)
			_ = os.Remove(pidFile)
		}
	}
	return false, nil
}

// processRunningFn and isAboxProcessFn are package-level seams so tests can
// drive daemonStateOf deterministically without spawning real processes. They
// default to the real implementations.
var (
	processRunningFn = isProcessRunning
	isAboxProcessFn  = daemon.IsAboxProcess
)

// daemonStateOf classifies the daemon referenced by pidFile. A missing/garbage
// PID file or a dead/not-abox PID is daemonDead; a confirmed-abox live PID is
// daemonAlive; a live PID whose identity can't be confirmed is
// daemonUnverifiable.
func daemonStateOf(pidFile string) daemonState {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return daemonDead
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return daemonDead
	}
	if !processRunningFn(pid) {
		return daemonDead
	}
	isAbox, idErr := isAboxProcessFn(pid)
	if idErr != nil {
		// Process is alive but we couldn't confirm whether it is ours. Distinct
		// from a confirmed mismatch: do not touch its files.
		return daemonUnverifiable
	}
	if !isAbox {
		// Live, but confirmed to be some other program (PID reuse). Treat like a
		// stale file: safe to clean up and respawn.
		return daemonDead
	}
	return daemonAlive
}

// isProcessRunning checks if a process with the given PID is still running.
func isProcessRunning(pid int) bool {
	// On Unix, sending signal 0 checks if process exists without sending a signal
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// verifySocketPermissions checks that the socket has restrictive permissions.
// Returns an error if permissions are too permissive.
func verifySocketPermissions(info os.FileInfo, daemonType string) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s socket has insecure permissions %o (expected 0o600 or stricter)",
			daemonType, info.Mode().Perm())
	}
	return nil
}
