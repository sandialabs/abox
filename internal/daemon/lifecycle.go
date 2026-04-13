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

// isAboxProcess verifies that a PID belongs to an abox process.
// This prevents signaling unrelated processes if the PID was reused.
func isAboxProcess(pid int) bool {
	// Check /proc/{pid}/exe symlink to verify the process is running our executable.
	// This is more secure than checking cmdline, which could match any process
	// that happens to have "abox" in its arguments (e.g., "cat /home/abox/file").
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	currentExe, err := os.Executable()
	if err != nil {
		return false
	}
	return exePath == currentExe
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
	if !isAboxProcess(pid) {
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
