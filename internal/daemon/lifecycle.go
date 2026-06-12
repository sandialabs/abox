// Package daemon provides lifecycle management for abox daemon processes.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// rpcShutdownFunc is the signature for RPC shutdown methods (with variadic grpc.CallOption).
type rpcShutdownFunc func(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.Empty, error)

// stopDaemonViaRPC attempts to stop a daemon via RPC shutdown.
// Returns true if RPC shutdown was successful.
func stopDaemonViaRPC(socketPath string, shutdownFunc rpcShutdownFunc) bool {
	if _, err := os.Stat(socketPath); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, rpcErr := shutdownFunc(ctx, &rpc.Empty{})
	if rpcErr == nil {
		// Give it a moment to shut down
		time.Sleep(100 * time.Millisecond)
		return true
	}
	return false
}

// cleanupDaemonFiles removes daemon PID and socket files.
// Attempts both removals and returns a combined error if any fail.
func cleanupDaemonFiles(daemonName, pidFile, socketPath string) error {
	var errs []error
	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		logging.Warn("failed to remove PID file", "daemon", daemonName, "path", pidFile, "error", err)
		errs = append(errs, fmt.Errorf("remove PID file %s: %w", pidFile, err))
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logging.Warn("failed to remove socket", "daemon", daemonName, "path", socketPath, "error", err)
		errs = append(errs, fmt.Errorf("remove socket %s: %w", socketPath, err))
	}
	return errors.Join(errs...)
}

// sameExe reports whether an observed executable path refers to the same
// binary as our own resolved executable. The kernel appends " (deleted)" to
// /proc/<pid>/exe after the on-disk binary is replaced (e.g. an in-place abox
// upgrade); strip that suffix so a still-running daemon launched from the old
// inode is still recognized as ours.
func sameExe(observed, self string) bool {
	observed = strings.TrimSuffix(observed, " (deleted)")
	return observed == self
}

// IsAboxProcess verifies that a PID belongs to an abox process, preventing us
// from signaling unrelated processes if the PID was reused. It reports:
//
//	(true,  nil): the PID is confirmed to be running our executable.
//	(false, nil): the PID is confirmed NOT to be our executable.
//	(false, err): identity could NOT be determined (the process may or may not
//	              be ours). Callers MUST treat this as "do not signal / do not
//	              delete state" rather than as a confirmed mismatch.
//
// The platform-specific implementation lives in lifecycle_<os>.go; this wrapper
// only documents the shared contract.
func IsAboxProcess(pid int) (bool, error) {
	return isAboxProcess(pid)
}

// signalFallback reads a PID file and sends SIGTERM, then SIGKILL if needed.
// Used when RPC shutdown fails or is unavailable.
func signalFallback(pidFile string) {
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pidStr := strings.TrimSpace(string(pidBytes))
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return
	}
	// Only signal a PID we can positively confirm is ours. A mismatch (the PID
	// was reused by something else) or an unverifiable identity both mean "don't
	// signal": killing a reused PID would be worse than leaking a stale file.
	isAbox, idErr := IsAboxProcess(pid)
	if idErr != nil {
		logging.Warn("could not verify PID identity, skipping signal", "pid", pid, "error", idErr)
		return
	}
	if !isAbox {
		logging.Warn("PID is not an abox process, skipping signal", "pid", pid)
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		logging.Warn("failed to find daemon process", "pid", pid, "error", err)
		return
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		logging.Warn("failed to send SIGTERM to daemon", "pid", pid, "error", err)
		return
	}
	time.Sleep(500 * time.Millisecond)
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		logging.Warn("daemon did not stop gracefully, sending SIGKILL", "pid", pid)
		_ = proc.Kill()
	}
}

// StopDNSFilter stops the DNS filter process for an instance.
func StopDNSFilter(name string) {
	paths, err := config.GetPaths(name)
	if err != nil {
		return
	}

	rpcShutdownSucceeded := false

	// Try RPC shutdown first (preferred method)
	if client, err := rpc.UnixDial(paths.DNSSocket); err == nil {
		dnsClient := rpc.NewDNSFilterClient(client)
		rpcShutdownSucceeded = stopDaemonViaRPC(paths.DNSSocket, dnsClient.Shutdown)
		_ = client.Close()
	}

	// If RPC shutdown failed, try SIGTERM/SIGKILL fallback
	if !rpcShutdownSucceeded {
		signalFallback(paths.DNSPIDFile)
	}

	_ = cleanupDaemonFiles("dnsfilter", paths.DNSPIDFile, paths.DNSSocket)
}

// StopHTTPFilter stops the HTTP filter process for an instance.
func StopHTTPFilter(name string) {
	paths, err := config.GetPaths(name)
	if err != nil {
		return
	}

	rpcShutdownSucceeded := false

	// Try RPC shutdown first (preferred method)
	if client, err := rpc.UnixDial(paths.HTTPSocket); err == nil {
		httpClient := rpc.NewHTTPFilterClient(client)
		rpcShutdownSucceeded = stopDaemonViaRPC(paths.HTTPSocket, httpClient.Shutdown)
		_ = client.Close()
	}

	// If RPC shutdown failed, try SIGTERM/SIGKILL fallback
	if !rpcShutdownSucceeded {
		signalFallback(paths.HTTPPIDFile)
	}

	_ = cleanupDaemonFiles("httpfilter", paths.HTTPPIDFile, paths.HTTPSocket)
}

// StopMonitorDaemon stops the monitor daemon process for an instance.
func StopMonitorDaemon(name string) {
	paths, err := config.GetPaths(name)
	if err != nil {
		return
	}

	rpcShutdownSucceeded := false

	// Try RPC shutdown first (preferred method)
	if client, err := rpc.UnixDial(paths.MonitorRPCSocket); err == nil {
		monitorClient := rpc.NewMonitorClient(client)
		rpcShutdownSucceeded = stopDaemonViaRPC(paths.MonitorRPCSocket, monitorClient.Shutdown)
		_ = client.Close()
	}

	// If RPC shutdown failed, try SIGTERM/SIGKILL fallback
	if !rpcShutdownSucceeded {
		signalFallback(paths.MonitorPIDFile)
	}

	_ = cleanupDaemonFiles("monitor", paths.MonitorPIDFile, paths.MonitorRPCSocket)
}
