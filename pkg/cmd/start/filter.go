package start

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

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
func startFilter(name string, filterType FilterType, paths FilterPaths, logLevel string) error {
	// Check if already running by looking for socket
	if _, err := os.Stat(paths.Socket); err == nil {
		logging.Warn("filter already running", "type", string(filterType))
		return nil
	}

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
func startDaemon(name string, daemonType string, paths DaemonPaths) error {
	// Check if already running by looking for socket
	if _, err := os.Stat(paths.Socket); err == nil {
		logging.Warn("daemon already running", "type", daemonType)
		return nil
	}

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
			return fmt.Errorf("%s daemon exited immediately after starting", opts.daemonType)
		}

		if info, err := os.Stat(opts.socketPath); err == nil {
			return verifySocketPermissions(info, opts.daemonType)
		}
	}

	return fmt.Errorf("%s daemon started but socket not ready", opts.daemonType)
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
