package start

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/daemon"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/procutil"
	"github.com/sandialabs/abox/internal/sysutil"
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
	if checkAlreadyRunning(w, string(filterType), paths.PIDFile, paths.Socket) {
		return nil
	}

	// The PID file says no daemon is alive, but on macOS a real daemon can still
	// be running with a purged/stale PID file and holding its port. Reclaim any
	// such orphan so the fresh spawn below can bind. No-op off darwin.
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
	if checkAlreadyRunning(w, daemonType, paths.PIDFile, paths.Socket) {
		return nil
	}

	// Reclaim an orphaned daemon holding this instance's socket/port after a
	// $TMPDIR purge left its PID file stale (macOS only; no-op elsewhere).
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

	// Spawn daemon as a background process
	cmd := exec.Command(exe, opts.args...)
	cmd.Stdout = opts.logFile
	cmd.Stderr = opts.logFile
	cmd.Dir = "/"

	// Detach from parent process group so the daemon outlives this command.
	procutil.Detach(cmd)

	// Set restrictive umask before spawning to ensure the socket is created with
	// owner-only permissions, closing a race window before the explicit chmod.
	var startErr error
	sysutil.WithRestrictiveUmask(func() {
		startErr = cmd.Start()
	})

	if startErr != nil {
		if opts.logFile != nil {
			opts.logFile.Close()
		}
		return fmt.Errorf("failed to start %s daemon: %w", opts.daemonType, startErr)
	}

	pid := cmd.Process.Pid

	// Reap the child in the background. Without this the daemon lingers as a
	// zombie when it dies early, and kill(pid, 0) on a zombie still succeeds — so
	// the liveness check below would miss the exit and every startup failure would
	// surface as the generic "socket not ready" instead of the real cause.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

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
		select {
		case waitErr := <-exited:
			return fmt.Errorf("%s daemon exited immediately after starting: %w", opts.daemonType, waitErr)
		default:
		}

		if info, err := os.Stat(opts.socketPath); err == nil {
			return verifySocketPermissions(info, opts.daemonType)
		}
	}

	return fmt.Errorf("%s daemon started but socket not ready", opts.daemonType)
}

// checkAlreadyRunning reports whether a daemon is already alive based on its
// PID file AND socket. A live daemon must have both: the PID file names a live
// abox process and the socket exists. If the PID is live but the socket is
// missing (a half-started or defunct daemon for this instance, or a reused PID),
// it kills that PID and clears the stale files so the caller respawns — this
// avoids the trap where start skips the spawn on a live PID and the later
// connect fails because no socket was ever created. If the PID is dead but
// socket/PID files remain (an ungraceful previous exit), it likewise removes the
// stale files. In both recovery cases it prints a user-visible notice and
// returns false.
func checkAlreadyRunning(w io.Writer, daemonType, pidFile, socketPath string) bool {
	if w == nil {
		w = io.Discard
	}
	if isDaemonAlive(pidFile) {
		if _, err := os.Stat(socketPath); err == nil {
			logging.Warn("daemon already running", "type", daemonType)
			return true
		}
		// PID alive but socket absent: the daemon never finished coming up (or the
		// PID was reused). Kill it and clear the files so a fresh spawn can bind.
		fmt.Fprintf(w, "  %s daemon PID is alive but its socket is missing, restarting...\n", daemonType)
		logging.Warn("daemon pid alive but socket missing; killing stale daemon", "type", daemonType)
		daemon.KillDaemonByPIDFile(pidFile)
		_ = os.Remove(socketPath)
		_ = os.Remove(pidFile)
		return false
	}
	_, socketErr := os.Stat(socketPath)
	_, pidErr := os.Stat(pidFile)
	if socketErr == nil || pidErr == nil {
		fmt.Fprintf(w, "  %s daemon from previous run did not exit cleanly, restarting...\n", daemonType)
		logging.Warn("cleaning up stale daemon files from previous crash", "type", daemonType)
		_ = os.Remove(socketPath)
		_ = os.Remove(pidFile)
	}
	return false
}

// isDaemonAlive returns true only if pidFile holds a live abox process.
// Any read/parse error, dead PID, or non-abox PID is treated as "not alive"
// since each leads to the same caller action: clean up and start fresh.
func isDaemonAlive(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return false
	}
	return isProcessRunning(pid) && daemon.IsAboxProcess(pid)
}

// isProcessRunning checks if a process with the given PID is still running.
func isProcessRunning(pid int) bool {
	return procutil.IsAlive(pid)
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
