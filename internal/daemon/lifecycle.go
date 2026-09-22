// Package daemon provides lifecycle management for abox daemon processes.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/procutil"
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

// IsAboxProcess verifies that a PID belongs to an abox process.
// This prevents signaling unrelated processes if the PID was reused.
//
// It delegates to the per-OS isAboxProcess, which returns:
//   - (true, nil)  — the PID is positively confirmed to be our executable.
//   - (false, nil) — the PID is positively confirmed NOT to be our executable.
//   - (false, err) — the PID could not be verified either way (e.g. it is gone,
//     or is owned by another user we cannot introspect).
//
// Callers use this as a fail-safe gate before signaling: they must only act on
// a positive confirmation. To honor that intent, an unverifiable result (error)
// is mapped to false here — we never signal a process we cannot positively
// confirm is abox. Only (true, nil) yields true.
func IsAboxProcess(pid int) bool {
	ok, err := isAboxProcess(pid)
	if err != nil {
		// Unverifiable: do not treat as ours. Callers must not signal it.
		return false
	}
	return ok
}

// VerifyAboxProcess reports whether pid is our executable, preserving the
// three-way result of the per-OS check: (true, nil) confirmed ours,
// (false, nil) confirmed NOT ours, (false, err) unverifiable. Prefer
// IsAboxProcess for a simple signal gate; use this when the caller wants to
// distinguish "confirmed other" from "could not verify" (e.g. to log and leave a
// candidate process alone rather than silently skip it).
func VerifyAboxProcess(pid int) (bool, error) {
	return isAboxProcess(pid)
}

// sameExe reports whether an observed executable path refers to our own
// executable. The kernel appends a " (deleted)" suffix to /proc/<pid>/exe after
// the binary has been replaced on disk (e.g. an in-place upgrade); that suffix
// is stripped before comparison so an upgraded abox still recognizes daemons it
// launched from the pre-upgrade binary.
func sameExe(observed, self string) bool {
	observed = strings.TrimSuffix(observed, " (deleted)")
	return observed == self
}

// verifyAboxProcess is the identity gate signalFallback uses before signalling.
// It is a var (defaulting to IsAboxProcess) so tests can drive the SIGKILL
// escalation decision deterministically.
var verifyAboxProcess = IsAboxProcess

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
	if !verifyAboxProcess(pid) {
		logging.Warn("PID is not an abox process, skipping signal", "pid", pid)
		return
	}
	if err := procutil.TerminatePID(pid); err != nil {
		logging.Warn("failed to send SIGTERM to daemon", "pid", pid, "error", err)
		return
	}
	time.Sleep(500 * time.Millisecond)
	if procutil.IsAlive(pid) {
		// Re-verify identity before escalating: during the grace window the daemon
		// may have exited and the OS reused its PID for an unrelated process. Only
		// SIGKILL a PID still confirmed to be ours, mirroring supervisor.Stop.
		if !verifyAboxProcess(pid) {
			logging.Warn("PID no longer an abox process after SIGTERM (likely exited and PID reused); not sending SIGKILL", "pid", pid)
			return
		}
		logging.Warn("daemon did not stop gracefully, sending SIGKILL", "pid", pid)
		if err := procutil.KillPID(pid); err != nil {
			logging.Warn("failed to send SIGKILL to daemon", "pid", pid, "error", err)
		}
	}
}

// KillDaemonByPIDFile terminates the daemon named by pidFile (SIGTERM, then
// SIGKILL if needed), re-verifying the PID is an abox process before signalling.
// It is a no-op if the file is missing/unparseable or the PID is not ours.
// Used to reclaim a half-started daemon whose PID is alive but whose socket
// never appeared, so a fresh spawn can proceed.
func KillDaemonByPIDFile(pidFile string) {
	signalFallback(pidFile)
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
