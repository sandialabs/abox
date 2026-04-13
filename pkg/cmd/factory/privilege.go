package factory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/internal/rpc"
)

// helperState represents the lifecycle state of a PrivilegeHelper.
type helperState int

const (
	helperIdle     helperState = iota // not started
	helperRunning                     // started and accepting requests
	helperShutdown                    // was running, now shut down
)

// PrivilegeHelper manages communication with the privileged helper process.
type PrivilegeHelper struct {
	mu         sync.Mutex
	cmd        *exec.Cmd // nil if using external helper
	conn       *grpc.ClientConn
	client     rpc.PrivilegeClient
	token      string
	socketPath string
	logPath    string   // instance-specific log path
	logFile    *os.File // open log file handle
	errOut     io.Writer
	waitDone   chan error // result of cmd.Wait(), shared between waitForSocket and Shutdown
	state      helperState
	external   bool // true if using external helper via env vars
}

// connectExternalHelper connects to an existing privilege helper via env vars.
func connectExternalHelper(socketPath, token string) (*PrivilegeHelper, error) {
	// Validate socket path for security
	if err := validateExternalSocketPath(socketPath); err != nil {
		return nil, fmt.Errorf("invalid external helper socket: %w", err)
	}

	conn, err := rpc.UnixDial(socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to external helper at %s: %w", socketPath, err)
	}

	client := rpc.NewPrivilegeClientWithToken(conn, token)

	// Verify the connection works
	ctx, cancel := context.WithTimeout(context.Background(), HelperPingTimeout)
	defer cancel()

	if _, err := client.Ping(ctx, &rpc.Empty{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("external helper ping failed: %w", err)
	}

	logging.Debug("connected to external privilege helper", "socket", socketPath)

	return &PrivilegeHelper{
		conn:       conn,
		client:     client,
		token:      token,
		socketPath: socketPath,
		state:      helperRunning,
		external:   true,
	}, nil
}

// validateExternalSocketPath validates an external helper socket path for security.
func validateExternalSocketPath(socketPath string) error {
	// Must be an absolute path
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("socket path must be absolute: %s", socketPath)
	}

	// Use Lstat to avoid following symlinks
	info, err := os.Lstat(socketPath) //nolint:gosec // Lstat specifically avoids following symlinks for security
	if err != nil {
		return fmt.Errorf("socket path does not exist: %w", err)
	}

	// Verify it's actually a socket (not a symlink or other file type)
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path is not a socket: %s", socketPath)
	}

	// Verify socket is owned by the current user
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) { //nolint:gosec // UID is always non-negative
		return fmt.Errorf("socket not owned by current user (uid %d): %s", os.Getuid(), socketPath)
	}

	// Verify socket is in a secure directory (XDG_RUNTIME_DIR or /run/user/<uid>)
	// This prevents using sockets in world-writable directories like /tmp
	uid := os.Getuid()
	allowedPrefixes := []string{
		filepath.Clean(fmt.Sprintf("/run/user/%d", uid)) + "/",
	}
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		allowedPrefixes = append(allowedPrefixes, filepath.Clean(xdgRuntime)+"/")
	}

	cleanPath := filepath.Clean(socketPath)
	allowed := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cleanPath, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("socket must be in XDG_RUNTIME_DIR or /run/user/%d: %s", uid, socketPath)
	}

	return nil
}

// findSetuidHelper checks for an installed setuid abox-helper binary.
// Returns the path if found and valid, or empty string if not available.
//
// The helper must meet all criteria:
//  1. Exists at a known location
//  2. Owned by root
//  3. Has setuid bit set
//  4. Group is "abox"
//  5. Calling user is in the "abox" group
func findSetuidHelper() string {
	candidates := []string{
		"/usr/local/bin/abox-helper",
		"/usr/bin/abox-helper",
	}

	for _, path := range candidates {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}

		// Must be a regular file (not a symlink or directory)
		if !info.Mode().IsRegular() {
			logging.Debug("setuid helper is not a regular file", "path", path, "mode", info.Mode())
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		// Must be owned by root
		if stat.Uid != 0 {
			logging.Debug("setuid helper not owned by root", "path", path, "uid", stat.Uid)
			continue
		}

		// Must have setuid bit set
		if info.Mode()&os.ModeSetuid == 0 {
			logging.Debug("setuid helper missing setuid bit", "path", path)
			continue
		}

		// Must have group "abox"
		if !isGroupAbox(stat.Gid) {
			logging.Debug("setuid helper not in abox group", "path", path, "gid", stat.Gid)
			continue
		}

		// Calling user must be in "abox" group
		if !privilege.InGroup("abox") {
			logging.Debug("current user not in abox group")
			continue
		}

		logging.Debug("found setuid helper", "path", path)
		return path
	}

	return ""
}

// isGroupAbox checks if a GID belongs to the "abox" group.
func isGroupAbox(gid uint32) bool {
	g, err := user.LookupGroupId(strconv.Itoa(int(gid)))
	if err != nil {
		return false
	}
	return g.Name == "abox"
}

// buildSudoPkexecCmd creates an exec.Cmd that runs the privilege helper via sudo or pkexec.
// Returns nil if no privilege escalation tool is available.
func buildSudoPkexecCmd(h *PrivilegeHelper, helperSubcmdArgs []string) *exec.Cmd {
	aboxPath, err := privilege.FindAboxBinary()
	if err != nil {
		logging.Debug("failed to find abox binary for fallback", "error", err)
		return nil
	}
	helperArgs := append([]string{"privilege-helper"}, helperSubcmdArgs...)
	tool, err := privilege.SelectEscalationTool()
	if err != nil {
		logging.Debug("no privilege escalation tool available", "error", err)
		return nil
	}
	logging.Debug("selected privilege escalation method", "method", tool)
	errOut := h.errOut
	if errOut == nil {
		errOut = os.Stderr
	}
	fmt.Fprintln(errOut, "Requesting elevated privileges...")
	return exec.Command(tool, append([]string{aboxPath}, helperArgs...)...)
}

// cleanStalePrivilegeSockets removes orphaned privilege helper sockets.
// These can be left behind if abox is killed with SIGKILL or crashes.
func cleanStalePrivilegeSockets(socketDir string) {
	pattern := filepath.Join(socketDir, "abox-privilege-*.sock")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	for _, sockPath := range matches {
		// Check if socket is stale by attempting to connect
		conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			continue
		}
		// Socket is stale - no process listening
		if removeErr := os.Remove(sockPath); removeErr == nil {
			logging.Debug("removed stale privilege socket", "path", sockPath)
		}
	}
}

// start starts the helper process.
func (h *PrivilegeHelper) start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != helperIdle {
		return nil
	}

	// Clean up stale sockets from crashed/killed abox processes
	cleanStalePrivilegeSockets(filepath.Dir(h.socketPath))

	// Remove any stale socket at our specific path
	os.Remove(h.socketPath)

	// Pass our UID so the helper only accepts connections from our user.
	// The setuid binary uses the kernel-provided real UID and does not accept
	// --allowed-uid; the sudo/pkexec path needs it because sudo changes the real UID to root.
	ourUID := strconv.Itoa(os.Getuid())

	socketArgs := []string{"--socket", h.socketPath}
	helperSubcmdArgs := []string{"--socket", h.socketPath, "--allowed-uid", ourUID}

	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		// Already root: use abox privilege-helper subcommand directly
		aboxPath, err := privilege.FindAboxBinary()
		if err != nil {
			return fmt.Errorf("failed to find abox binary: %w", err)
		}
		cmd = exec.Command(aboxPath, append([]string{"privilege-helper"}, helperSubcmdArgs...)...)
	} else if setuidPath := findSetuidHelper(); setuidPath != "" {
		// Setuid helper available: spawn directly without sudo/pkexec.
		// No --allowed-uid: the setuid binary uses os.Getuid() (unforgeable).
		logging.Debug("using setuid helper", "path", setuidPath)
		cmd = exec.Command(setuidPath, socketArgs...)
	} else {
		cmd = buildSudoPkexecCmd(h, helperSubcmdArgs)
		if cmd == nil {
			return errors.New("no privilege escalation method available")
		}
	}

	// Set up stdin pipe to send the auth token
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Set up logging
	if err := h.setupCmdLogging(cmd); err != nil {
		return err
	}

	if startErr := cmd.Start(); startErr != nil {
		h.closeLogFile()
		cmd, stdin, err = h.startFallback(helperSubcmdArgs, startErr)
		if err != nil {
			return err
		}
	}

	// Send the auth token to the helper via stdin
	if _, err := io.WriteString(stdin, h.token+"\n"); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("failed to send token to helper: %w", err)
	}
	stdin.Close()

	h.cmd = cmd
	h.state = helperRunning

	// Wait for socket to be available
	logging.Debug("waiting for privilege helper socket", "path", h.socketPath)
	if err := h.waitForSocket(); err != nil {
		h.cleanup()
		return fmt.Errorf("helper did not start properly: %w", err)
	}
	logging.Debug("privilege helper socket found")

	// Connect to the helper
	logging.Debug("connecting to privilege helper")
	conn, err := rpc.UnixDial(h.socketPath)
	if err != nil {
		h.cleanup()
		return fmt.Errorf("failed to connect to helper: %w", err)
	}

	h.conn = conn
	h.client = rpc.NewPrivilegeClientWithToken(conn, h.token)

	// Verify the helper is working
	logging.Debug("pinging privilege helper")
	ctx, cancel := context.WithTimeout(context.Background(), HelperPingTimeout)
	defer cancel()

	_, err = h.client.Ping(ctx, &rpc.Empty{})
	if err != nil {
		h.cleanup()
		return fmt.Errorf("helper ping failed: %w", err)
	}
	logging.Debug("privilege helper ready")

	return nil
}

// setupCmdLogging configures stderr logging for a helper command.
func (h *PrivilegeHelper) setupCmdLogging(cmd *exec.Cmd) error {
	if h.logPath == "" {
		cmd.Stderr = os.Stderr
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(h.logPath), 0o700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logFile, err := os.OpenFile(h.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create privilege helper log: %w", err)
	}
	cmd.Stderr = logFile
	h.logFile = logFile
	return nil
}

// closeLogFile closes and nils the log file handle if open.
func (h *PrivilegeHelper) closeLogFile() {
	if h.logFile != nil {
		h.logFile.Close()
		h.logFile = nil
	}
}

// startFallback attempts to start the helper via sudo/pkexec after a setuid exec failure.
func (h *PrivilegeHelper) startFallback(helperSubcmdArgs []string, startErr error) (*exec.Cmd, io.WriteCloser, error) {
	if findSetuidHelper() == "" || os.Geteuid() == 0 {
		return nil, nil, fmt.Errorf("failed to start helper: %w", startErr)
	}

	logging.Debug("setuid helper exec failed, falling back to sudo/pkexec", "error", startErr)
	cmd := buildSudoPkexecCmd(h, helperSubcmdArgs)
	if cmd == nil {
		return nil, nil, fmt.Errorf("failed to start setuid helper (%w) and no sudo/pkexec fallback available", startErr)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stdin pipe for fallback: %w", err)
	}
	if err := h.setupCmdLogging(cmd); err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		h.closeLogFile()
		return nil, nil, fmt.Errorf("failed to start helper via fallback: %w (setuid error: %w)", err, startErr)
	}
	return cmd, stdin, nil
}

// waitForSocket waits for the socket file to appear.
// It also monitors if the process exits early (e.g., user dismissed pkexec prompt).
func (h *PrivilegeHelper) waitForSocket() error {
	// Start a single goroutine to wait for the process to exit.
	// The result is shared with Shutdown() to avoid calling cmd.Wait() twice.
	h.waitDone = make(chan error, 1)
	go func() {
		h.waitDone <- h.cmd.Wait()
	}()

	ticker := time.NewTicker(HelperPollInterval)
	defer ticker.Stop()

	iterations := int(HelperStartTimeout / HelperPollInterval)
	for range iterations {
		// Check if socket exists and is connectable (os.Stat alone races
		// with chmod on the freshly-created root-owned socket).
		if _, err := os.Stat(h.socketPath); err == nil {
			conn, dialErr := net.DialTimeout("unix", h.socketPath, 100*time.Millisecond)
			if dialErr == nil {
				conn.Close()
				return nil
			}
		}

		// Check if process has exited
		select {
		case err := <-h.waitDone:
			// Re-buffer so cleanup()/Shutdown() can drain without deadlocking.
			h.waitDone <- err
			if err != nil {
				return fmt.Errorf("privilege helper exited: %w (authentication cancelled?)", err)
			}
			return errors.New("privilege helper exited unexpectedly (authentication cancelled?)")
		case <-ticker.C:
			// Continue waiting
		}
	}
	return fmt.Errorf("timeout waiting for privilege helper (%v)", HelperStartTimeout)
}

// Shutdown gracefully shuts down the helper.
func (h *PrivilegeHelper) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != helperRunning {
		return
	}

	h.state = helperShutdown

	// For external helpers, just close the connection without shutdown RPC
	// The external helper is shared and managed by its spawner
	if h.external {
		if h.conn != nil {
			if err := h.conn.Close(); err != nil {
				logging.Debug("failed to close external helper connection", "error", err)
			}
		}
		return
	}

	// Ask the helper to shut itself down via RPC
	if h.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), HelperShutdownTimeout)
		_, _ = h.client.Shutdown(ctx, &rpc.Empty{})
		cancel()
	}

	// Wait for the helper process to exit using the shared waitDone channel
	// (started in waitForSocket to avoid calling cmd.Wait() twice)
	if h.waitDone != nil {
		select {
		case <-h.waitDone:
			// Process exited
		case <-time.After(HelperShutdownTimeout):
			// If it didn't exit, force kill (shouldn't happen)
			if h.cmd != nil && h.cmd.Process != nil {
				_ = h.cmd.Process.Kill()
			}
			<-h.waitDone
		}
	}

	h.closeResources()
}

// cleanup cleans up resources after a failed start.
func (h *PrivilegeHelper) cleanup() {
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		if h.waitDone != nil {
			// Drain the goroutine started in waitForSocket() to avoid
			// a concurrent cmd.Wait() call (which is not safe).
			<-h.waitDone
		} else {
			_ = h.cmd.Wait()
		}
	}
	h.closeResources()
	h.state = helperIdle
}

// closeResources closes shared resources (connection, socket, log file).
func (h *PrivilegeHelper) closeResources() {
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			logging.Debug("failed to close privilege helper connection", "error", err)
		}
	}
	if err := os.Remove(h.socketPath); err != nil && !os.IsNotExist(err) {
		logging.Debug("failed to remove privilege helper socket", "path", h.socketPath, "error", err)
	}
	if h.logFile != nil {
		if err := h.logFile.Close(); err != nil {
			logging.Debug("failed to close privilege helper log file", "error", err)
		}
		h.logFile = nil
	}
}
