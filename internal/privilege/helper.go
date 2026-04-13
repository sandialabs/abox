package privilege

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// resolvedCommands holds absolute paths for external commands.
// These are resolved once at startup and cached for the process lifetime.
var resolvedCommands struct {
	mu       sync.RWMutex
	resolved bool
	paths    map[string]string
}

// ResolveCommands resolves absolute paths for all external commands used
// by the privilege helper. This should be called once at startup.
// In setuid context, PATH is sanitized but absolute paths provide defense-in-depth.
func ResolveCommands() error {
	resolvedCommands.mu.Lock()
	defer resolvedCommands.mu.Unlock()

	if resolvedCommands.resolved {
		return nil
	}

	resolvedCommands.paths = make(map[string]string)

	commands := []struct {
		name     string
		required bool
	}{
		{"iptables", true},
		{"qemu-img", true},
		{"chmod", true},
		{"ufw", false}, // Optional: not all systems use ufw
	}

	for _, entry := range commands {
		path, err := exec.LookPath(entry.name)
		if err != nil {
			if entry.required {
				return fmt.Errorf("required command %q not found in PATH: %w", entry.name, err)
			}
			continue
		}
		// Use absolute path but do NOT resolve symlinks.
		// iptables is a multi-call binary (xtables-nft-multi) that uses
		// argv[0] to determine behavior. Resolving symlinks breaks it.
		abs, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for %q: %w", entry.name, err)
		}
		resolvedCommands.paths[entry.name] = abs
	}

	resolvedCommands.resolved = true
	return nil
}

// safeEnv is the minimal environment for child processes.
// Defense-in-depth: even though the setuid binary clears its own environment
// at startup, explicitly setting cmd.Env prevents any env vars set by Go
// runtime or library code from leaking to iptables, qemu-img, chmod, etc.
var safeEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// safeCommand creates an exec.Cmd with an explicit minimal environment
// and explicit root credentials. The credential setting ensures child
// processes run with ruid=0/euid=0 even when the helper itself is a setuid
// binary (euid=0 but ruid=calling-user). Without this, iptables-nft fails
// because its netlink backend checks the real UID.
func safeCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = safeEnv
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	return cmd
}

// cmdPath returns the absolute path for a command, falling back to the bare
// name if ResolveCommands hasn't been called (backwards compatibility).
func cmdPath(name string) string {
	resolvedCommands.mu.RLock()
	defer resolvedCommands.mu.RUnlock()

	if resolvedCommands.resolved {
		if p, ok := resolvedCommands.paths[name]; ok && p != "" {
			return p
		}
	}
	return name
}

// cmdResolved reports whether a command was successfully resolved to an
// absolute path. Returns false if ResolveCommands hasn't been called or
// if the command was not found (e.g., optional commands like ufw).
func cmdResolved(name string) bool {
	resolvedCommands.mu.RLock()
	defer resolvedCommands.mu.RUnlock()

	if !resolvedCommands.resolved {
		return false
	}
	_, ok := resolvedCommands.paths[name]
	return ok
}

// setCmdPath caches an absolute path for a command that was resolved after
// startup (e.g., optional commands discovered at runtime).
func setCmdPath(name, path string) {
	resolvedCommands.mu.Lock()
	defer resolvedCommands.mu.Unlock()

	if resolvedCommands.paths == nil {
		resolvedCommands.paths = make(map[string]string)
	}
	resolvedCommands.paths[name] = path
}

// PrivilegeServer implements the gRPC Privilege service.
type PrivilegeServer struct {
	rpc.UnimplementedPrivilegeServer
	allowedUID int
}

// RunHelper runs the privileged helper gRPC server.
// It listens on a Unix socket and handles privileged operations.
// Authentication is token-based: the token is read from stdin on startup,
// and all RPC calls (except Ping) must include the token in metadata.
// The allowedUID parameter restricts socket connections to that UID.
func RunHelper(socketPath string, allowedUID int) error {
	// Verify we're running as root
	if os.Geteuid() != 0 {
		return errors.New("privilege-helper must be run as root (via pkexec/sudo); this is an internal command used by abox, do not run it directly")
	}

	if allowedUID < 0 {
		return errors.New("--allowed-uid is required for security")
	}

	// Ensure command paths are resolved (idempotent due to resolved flag).
	// The setuid binary calls ResolveCommands() explicitly before RunHelper(),
	// but the cobra subcommand path may not, so resolve here as a safety net.
	if err := ResolveCommands(); err != nil {
		return fmt.Errorf("failed to resolve command paths: %w", err)
	}

	// Read token from stdin (sent by parent process)
	token, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read token from stdin: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("empty token received")
	}
	// Minimum 32 characters (128 bits) for security; we generate 64 hex chars (256 bits)
	if len(token) < 32 {
		return errors.New("token too short (minimum 32 characters)")
	}
	if len(token) > 256 {
		return errors.New("token too long (maximum 256 characters)")
	}

	listener, err := rpc.UnixListenWithUIDCheck(socketPath, allowedUID)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}
	defer func() { _ = listener.Close() }()
	defer os.Remove(socketPath)

	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			tokenAuthInterceptor(token),
			auditInterceptor(),
		),
	)
	rpc.RegisterPrivilegeServer(server, &PrivilegeServer{allowedUID: allowedUID})

	// Store shutdown state under mutex for coordinated shutdown
	shutdownState.mu.Lock()
	shutdownState.server = server
	shutdownState.mu.Unlock()

	return server.Serve(listener)
}

// tokenAuthInterceptor returns a gRPC interceptor that validates the auth token.
// Ping is allowed without authentication to enable health checks.
func tokenAuthInterceptor(expectedToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Allow Ping without auth for health checks
		if info.FullMethod == rpc.Privilege_Ping_FullMethodName {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		tokens := md.Get("authorization")
		if len(tokens) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization token")
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(expectedToken)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization token")
		}

		return handler(ctx, req)
	}
}

// auditInterceptor returns a gRPC interceptor that logs every RPC call to syslog.
// This provides an audit trail for all privileged operations, replacing the
// sudo audit trail that would otherwise be lost with the setuid helper.
// The caller UID is already logged once at startup (main.go); per-RPC logs
// include only the method and result to avoid redundancy.
func auditInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Skip auditing Ping (health check noise)
		if info.FullMethod == rpc.Privilege_Ping_FullMethodName {
			return handler(ctx, req)
		}

		resp, err := handler(ctx, req)

		if err != nil {
			errMsg := err.Error()
			if len(errMsg) > 200 {
				errMsg = errMsg[:200]
			}
			logging.Audit("privilege-helper.rpc", "method", info.FullMethod, "result", "error", "error", errMsg)
		} else {
			logging.Audit("privilege-helper.rpc", "method", info.FullMethod, "result", "success")
		}

		return resp, err
	}
}

// Ping handles the ping operation (health check).
func (s *PrivilegeServer) Ping(ctx context.Context, req *rpc.Empty) (*rpc.StringMsg, error) {
	return &rpc.StringMsg{Message: "pong"}, nil
}

// shutdownState holds the gRPC server for coordinated shutdown.
var shutdownState struct {
	mu     sync.Mutex
	server *grpc.Server
}

// Shutdown gracefully terminates the helper process.
// GracefulStop causes server.Serve() to return, which lets deferred cleanup
// (socket removal) in RunHelper execute naturally.
func (s *PrivilegeServer) Shutdown(ctx context.Context, req *rpc.Empty) (*rpc.Empty, error) {
	go func() {
		// Brief delay to allow the RPC response to be sent
		time.Sleep(50 * time.Millisecond)

		shutdownState.mu.Lock()
		srv := shutdownState.server
		shutdownState.mu.Unlock()

		// Gracefully stop the gRPC server (drains in-flight RPCs).
		// This causes server.Serve() in RunHelper to return, allowing
		// deferred cleanup to run.
		if srv != nil {
			srv.GracefulStop()
		}
	}()
	return &rpc.Empty{}, nil
}

// QemuImgCreate creates a qemu disk image.
//
// Note: The output path has a TOCTOU window between ValidatePathNoSymlinks and
// the qemu-img exec (which takes a string path). The backing file is resolved
// via O_NOFOLLOW + /proc/self/fd (TOCTOU-safe). For the output path, there is no
// fd-based alternative since qemu-img requires a filename argument. Security
// relies on the parent directory being root-owned — see MkdirAll comment.
func (s *PrivilegeServer) QemuImgCreate(ctx context.Context, req *rpc.QemuImgReq) (*rpc.Empty, error) {
	if err := ValidatePathNoSymlinks(req.Output); err != nil {
		return nil, err
	}

	if !strings.HasSuffix(req.Output, ".qcow2") {
		return nil, fmt.Errorf("output must end with .qcow2: %s", req.Output)
	}

	if err := validateBackingFile(req.BackingFile); err != nil {
		return nil, err
	}

	if err := validateDiskSize(req.Size); err != nil {
		return nil, err
	}

	// Resolve the backing file to its real path in a TOCTOU-safe way.
	// We open with O_NOFOLLOW (kernel atomically refuses symlinks), then
	// read the real path from /proc/self/fd/<fd>. This gives us the actual
	// file path that the fd points to, which we then pass to qemu-img.
	realBackingFile, err := resolvePathNoFollow(req.BackingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve backing file: %w", err)
	}

	// Verify the resolved path is still in allowed directories
	if err := validateBackingFile(realBackingFile); err != nil {
		return nil, fmt.Errorf("resolved backing file not allowed: %w", err)
	}

	cmd := safeCommand(cmdPath("qemu-img"), "create",
		"-f", "qcow2",
		"-F", "qcow2",
		"-b", realBackingFile,
		req.Output,
		req.Size,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("qemu-img create failed: %s: %w", string(output), err)
	}

	return &rpc.Empty{}, nil
}

// Chmod changes file permissions.
// Uses O_PATH|O_NOFOLLOW + /proc/self/fd/<fd> to eliminate TOCTOU race
// between path validation and chmod execution.
func (s *PrivilegeServer) Chmod(ctx context.Context, req *rpc.ChmodReq) (*rpc.Empty, error) {
	if err := ValidatePathNoSymlinks(req.Path); err != nil {
		return nil, err
	}

	if err := ValidateChmodMode(req.Mode); err != nil {
		return nil, err
	}

	// Open with O_PATH|O_NOFOLLOW to pin the file without following symlinks.
	// Then use /proc/self/fd/<fd> so chmod operates on the pinned fd, not the
	// path string, eliminating the TOCTOU window.
	fd, err := unix.Open(req.Path, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("refusing to follow symlink: %s", req.Path)
		}
		return nil, fmt.Errorf("failed to open path: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	cmd := safeCommand(cmdPath("chmod"), req.Mode, fdPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to chmod: %s: %w", string(output), err)
	}

	return &rpc.Empty{}, nil
}

// MkdirAll creates directories.
//
// Note: There is an inherent TOCTOU window between ValidatePathNoSymlinks and
// os.MkdirAll because MkdirAll operates on a string path, not a file descriptor.
// An fd-based alternative (openat2 with RESOLVE_NO_SYMLINKS) doesn't exist for
// recursive directory creation in Go's stdlib. Adding an Lstat check would be
// equally racy and give false confidence. Security relies on the parent directory
// (/var/lib/libvirt/images/abox/) being root-owned with mode 755, so unprivileged
// users cannot create symlinks there.
func (s *PrivilegeServer) MkdirAll(ctx context.Context, req *rpc.MkdirReq) (*rpc.Empty, error) {
	if err := ValidatePathNoSymlinks(req.Path); err != nil {
		return nil, err
	}

	if err := ValidateChmodMode(req.Mode); err != nil {
		return nil, err
	}

	mode, err := strconv.ParseUint(req.Mode, 8, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid mode: %w", err)
	}

	if err := os.MkdirAll(req.Path, os.FileMode(mode)); err != nil {
		return nil, fmt.Errorf("failed to mkdir: %w", err)
	}

	return &rpc.Empty{}, nil
}

// RemoveAll removes a directory tree.
//
// Note: There is an inherent TOCTOU window between ValidatePathNoSymlinks and
// os.RemoveAll because RemoveAll operates on a string path. Go's os.RemoveAll
// does not have an fd-based variant (e.g., unlinkat with AT_REMOVEDIR for trees).
// Security relies on the parent directory being root-owned — see MkdirAll comment.
func (s *PrivilegeServer) RemoveAll(ctx context.Context, req *rpc.PathReq) (*rpc.Empty, error) {
	if err := ValidateRemoveAllPath(req.Path); err != nil {
		return nil, err
	}

	if err := ValidatePathNoSymlinks(req.Path); err != nil {
		return nil, err
	}

	if err := os.RemoveAll(req.Path); err != nil {
		return nil, fmt.Errorf("failed to remove: %w", err)
	}

	return &rpc.Empty{}, nil
}

// CopyFile copies a file.
// Uses O_NOFOLLOW to prevent symlink-based TOCTOU attacks on the source file.
func (s *PrivilegeServer) CopyFile(ctx context.Context, req *rpc.CopyReq) (*rpc.Empty, error) {
	if err := ValidatePathNoSymlinks(req.Dst); err != nil {
		return nil, err
	}

	if err := s.validateCopySource(req.Src); err != nil {
		return nil, err
	}

	// Open source with O_NOFOLLOW to prevent symlink TOCTOU attacks.
	// This makes the kernel refuse to open the file if it's a symlink,
	// eliminating the race window between validation and use.
	srcFile, err := openNoFollow(req.Src)
	if err != nil {
		return nil, fmt.Errorf("failed to open source: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat source: %w", err)
	}
	if !srcInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("source is not a regular file: %s", req.Src)
	}

	dstFile, err := os.OpenFile(req.Dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination: %w", err)
	}
	defer func() {
		// Only close if not already closed by the explicit Close below.
		if dstFile != nil {
			_ = dstFile.Close()
		}
	}()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return nil, fmt.Errorf("failed to copy: %w", err)
	}

	if err := dstFile.Chmod(srcInfo.Mode() & 0o644); err != nil {
		return nil, fmt.Errorf("failed to set permissions: %w", err)
	}

	// Explicitly close to check for flush errors (deferred close is a no-op safety net).
	err = dstFile.Close()
	dstFile = nil
	if err != nil {
		return nil, fmt.Errorf("failed to flush destination file: %w", err)
	}

	return &rpc.Empty{}, nil
}

// validateDiskSize validates a disk size string (e.g., "20G", "100M").
func validateDiskSize(size string) error {
	if len(size) < 2 {
		return fmt.Errorf("invalid disk size: %s", size)
	}

	suffix := size[len(size)-1]
	if suffix != 'G' && suffix != 'T' {
		return fmt.Errorf("disk size must use G or T suffix: %s", size)
	}

	numPart := size[:len(size)-1]
	num, err := strconv.Atoi(numPart)
	if err != nil || num <= 0 {
		return fmt.Errorf("disk size must be a positive integer: %s", size)
	}

	switch suffix {
	case 'T':
		if num > 10 {
			return fmt.Errorf("disk size must be at most 10T: %s", size)
		}
	case 'G':
		if num > 10240 {
			return fmt.Errorf("disk size must be at most 10T: %s", size)
		}
	}

	return nil
}

// openNoFollow opens a file with O_NOFOLLOW, preventing symlink traversal.
// This eliminates TOCTOU race conditions for symlink attacks because the kernel
// atomically refuses to open symlinks.
func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("refusing to follow symlink: %s", path)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil //nolint:gosec // fd comes from unix.Open, safe conversion
}

// resolvePathNoFollow opens a file with O_NOFOLLOW and returns its real path.
// This is TOCTOU-safe because:
// 1. O_NOFOLLOW atomically refuses to open symlinks (kernel enforced)
// 2. /proc/self/fd/<fd> gives us the real path of the open file
// 3. The returned path is what the fd actually points to
func resolvePathNoFollow(path string) (string, error) {
	// Open with O_NOFOLLOW - kernel atomically refuses if it's a symlink
	f, err := openNoFollow(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Verify it's a regular file
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", path)
	}

	// Read the real path from /proc/self/fd/<fd>
	// This gives us the actual path the fd points to
	fdPath := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	realPath, err := os.Readlink(fdPath)
	if err != nil {
		return "", fmt.Errorf("failed to read fd path: %w", err)
	}

	return realPath, nil
}

// validateBackingFile validates a backing file path for qemu-img.
// This includes symlink validation to prevent attackers from using symlinks
// to point qemu-img at files outside the allowed directories.
func validateBackingFile(path string) error {
	if err := ValidateArgs([]string{path}); err != nil {
		return err
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed in backing file: %s", path)
	}

	if !strings.HasSuffix(path, ".qcow2") {
		return fmt.Errorf("backing file must be .qcow2: %s", path)
	}

	cleanPath := filepath.Clean(path)

	for _, base := range allowedPaths {
		if strings.HasPrefix(cleanPath, base+"/") || cleanPath == base {
			// Validate no symlinks in path to prevent symlink attacks
			return ValidatePathNoSymlinks(path)
		}
	}

	return fmt.Errorf("backing file not in allowed paths: %s", path)
}

// UfwStatus checks if UFW is installed and active.
func (s *PrivilegeServer) UfwStatus(ctx context.Context, req *rpc.Empty) (*rpc.UfwStatusResp, error) {
	resp := &rpc.UfwStatusResp{}

	// Check if ufw is installed
	if !cmdResolved("ufw") {
		// Not resolved at startup; try LookPath as fallback and cache
		path, err := exec.LookPath("ufw")
		if err != nil {
			return resp, nil //nolint:nilerr // ufw not installed is a valid status, not an error
		}
		// Resolve symlinks to match ResolveCommands behavior
		abs, err := filepath.EvalSymlinks(path)
		if err != nil {
			return resp, nil //nolint:nilerr // can't resolve path; treat as not installed
		}
		setCmdPath("ufw", abs)
	}
	ufwPath := cmdPath("ufw")
	resp.Installed = true

	// Check if ufw is active
	cmd := safeCommand(ufwPath, "status")
	output, err := cmd.Output()
	if err != nil {
		return resp, nil //nolint:nilerr // can't query ufw status; assume inactive
	}
	resp.Active = strings.Contains(string(output), "Status: active")

	return resp, nil
}

// UfwAdd adds an allow rule for traffic on a bridge interface.
func (s *PrivilegeServer) UfwAdd(ctx context.Context, req *rpc.UfwReq) (*rpc.Empty, error) {
	if err := ValidateBridgeName(req.Bridge); err != nil {
		return nil, err
	}

	cmd := safeCommand(cmdPath("ufw"), "allow", "in", "on", req.Bridge)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ufw add failed: %s: %w", string(output), err)
	}

	return &rpc.Empty{}, nil
}

// UfwRemove removes an allow rule for traffic on a bridge interface.
func (s *PrivilegeServer) UfwRemove(ctx context.Context, req *rpc.UfwReq) (*rpc.Empty, error) {
	if err := ValidateBridgeName(req.Bridge); err != nil {
		return nil, err
	}

	cmd := safeCommand(cmdPath("ufw"), "delete", "allow", "in", "on", req.Bridge)
	output, err := cmd.CombinedOutput()
	// Ignore "Could not delete non-existent rule" for idempotency
	if err != nil && !strings.Contains(string(output), "Could not delete non-existent rule") {
		return nil, fmt.Errorf("ufw delete failed: %s: %w", string(output), err)
	}

	return &rpc.Empty{}, nil
}

// validateIptablesReq validates common fields of an iptables request.
func validateIptablesReq(req *rpc.IptablesReq) (string, error) {
	if err := ValidateBridgeName(req.Bridge); err != nil {
		return "", err
	}
	if req.Protocol != "udp" && req.Protocol != "tcp" {
		return "", fmt.Errorf("protocol must be 'udp' or 'tcp', got: %s", req.Protocol)
	}
	port := int(req.DnsPort)
	if port < 5353 || port > 65535 {
		return "", fmt.Errorf("dns_port must be between 5353 and 65535, got: %d", port)
	}
	return strconv.Itoa(port), nil
}

// IptablesAdd adds DNS redirect iptables rules.
// This adds both:
//  1. A NAT PREROUTING rule to redirect port 53 to the dnsfilter port
//  2. An INPUT rule to accept traffic on the dnsfilter port (required because
//     after REDIRECT the destination port changes, and we need to accept it)
func (s *PrivilegeServer) IptablesAdd(ctx context.Context, req *rpc.IptablesReq) (*rpc.Empty, error) {
	portStr, err := validateIptablesReq(req)
	if err != nil {
		return nil, err
	}

	// Add NAT PREROUTING rule to redirect port 53 to dnsfilter port
	cmd := safeCommand(cmdPath("iptables"),
		"-w", // Wait for xtables lock
		"-t", "nat",
		"-A", "PREROUTING",
		"-i", req.Bridge,
		"-p", req.Protocol,
		"--dport", dnsPort,
		"-j", "REDIRECT",
		"--to-port", portStr,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables NAT failed: %s: %w", string(output), err)
	}

	// Verify the NAT rule was actually added
	checkCmd := safeCommand(cmdPath("iptables"),
		"-w",
		"-t", "nat",
		"-C", "PREROUTING",
		"-i", req.Bridge,
		"-p", req.Protocol,
		"--dport", dnsPort,
		"-j", "REDIRECT",
		"--to-port", portStr,
	)
	if err := checkCmd.Run(); err != nil {
		return nil, errors.New("iptables NAT rule verification failed: rule not found after add")
	}

	// Add INPUT rule to accept traffic on the dnsfilter port.
	// After PREROUTING REDIRECT, the destination port is the dnsfilter port.
	inputCmd := safeCommand(cmdPath("iptables"),
		"-w",
		"-I", "INPUT", // Insert at top to ensure it's evaluated before DROP
		"-i", req.Bridge,
		"-p", req.Protocol,
		"--dport", portStr,
		"-j", "ACCEPT",
	)
	inputOutput, err := inputCmd.CombinedOutput()
	if err != nil {
		// Rollback the NAT rule
		rollbackCmd := safeCommand(cmdPath("iptables"),
			"-w", "-t", "nat", "-D", "PREROUTING",
			"-i", req.Bridge, "-p", req.Protocol,
			"--dport", dnsPort, "-j", "REDIRECT", "--to-port", portStr,
		)
		if rollbackErr := rollbackCmd.Run(); rollbackErr != nil {
			logging.Audit("privilege-helper.rpc", "error", "iptables NAT rollback failed", "bridge", req.Bridge, "error", rollbackErr.Error())
		}
		return nil, fmt.Errorf("iptables INPUT failed: %s: %w", string(inputOutput), err)
	}

	return &rpc.Empty{}, nil
}

// IptablesRemove removes DNS redirect iptables rules (both NAT and INPUT).
func (s *PrivilegeServer) IptablesRemove(ctx context.Context, req *rpc.IptablesReq) (*rpc.Empty, error) {
	portStr, err := validateIptablesReq(req)
	if err != nil {
		return nil, err
	}

	// Remove NAT PREROUTING rule
	cmd := safeCommand(cmdPath("iptables"),
		"-w", // Wait for xtables lock
		"-t", "nat",
		"-D", "PREROUTING",
		"-i", req.Bridge,
		"-p", req.Protocol,
		"--dport", dnsPort,
		"-j", "REDIRECT",
		"--to-port", portStr,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables NAT remove failed: %s: %w", string(output), err)
	}

	// Remove INPUT rule (ignore errors - rule may not exist)
	inputCmd := safeCommand(cmdPath("iptables"),
		"-w",
		"-D", "INPUT",
		"-i", req.Bridge,
		"-p", req.Protocol,
		"--dport", portStr,
		"-j", "ACCEPT",
	)
	_ = inputCmd.Run() // Ignore errors - rule may already be gone

	return &rpc.Empty{}, nil
}

// IptablesFlush removes ALL DNS redirect rules for a bridge interface.
// This is used to clean up stale rules before adding new ones (e.g., when
// dnsfilter restarts and gets a different port).
func (s *PrivilegeServer) IptablesFlush(ctx context.Context, req *rpc.IptablesFlushReq) (*rpc.Empty, error) {
	if err := ValidateBridgeName(req.Bridge); err != nil {
		return nil, err
	}

	// Flush NAT PREROUTING rules
	s.flushNATRules(req.Bridge)

	// Flush INPUT rules for dnsfilter ports
	s.flushInputRules(req.Bridge)

	return &rpc.Empty{}, nil
}

// maxFlushRules is the maximum number of iptables rules to delete in a single
// flush operation. This prevents resource exhaustion if an attacker manages to
// add a large number of rules matching the bridge pattern.
const maxFlushRules = 100

// dnsPort is the standard DNS port that iptables rules redirect from.
const dnsPort = "53"

// flushNATRules removes all NAT PREROUTING REDIRECT rules for a bridge.
//
// Security note: This function parses iptables -S output using strings.Fields().
// This is safe because:
//  1. The bridge name is validated before reaching this function (alphanumeric + hyphen only)
//  2. iptables -S output format is predictable: "-A CHAIN -i IFACE -p PROTO ..." with
//     space-separated fields. No shell interpretation occurs.
//  3. We match only lines containing our validated bridge name and specific rule patterns.
//  4. The parsed fields are passed directly to exec.Command without shell expansion.
func (s *PrivilegeServer) flushNATRules(bridge string) {
	listCmd := safeCommand(cmdPath("iptables"), "-w", "-t", "nat", "-S", "PREROUTING")
	output, err := listCmd.Output()
	if err != nil {
		return
	}

	var rulesToDelete []string
	for line := range strings.SplitSeq(string(output), "\n") {
		// Match rules like: -A PREROUTING -i ab-xxx -p udp -m udp --dport 53 -j REDIRECT --to-ports 34711
		if strings.Contains(line, "-i "+bridge) &&
			strings.Contains(line, "--dport "+dnsPort) &&
			strings.Contains(line, "-j REDIRECT") {
			rulesToDelete = append(rulesToDelete, line)
			if len(rulesToDelete) >= maxFlushRules {
				logging.Audit("privilege-helper.flush", "warning", "excessive NAT rules for bridge, truncating", "bridge", bridge, "limit", maxFlushRules)
				break
			}
		}
	}

	for i := len(rulesToDelete) - 1; i >= 0; i-- {
		rule := rulesToDelete[i]
		rule = strings.TrimPrefix(rule, "-A ")
		args := []string{"-w", "-t", "nat", "-D"}
		// strings.Fields safely splits on whitespace; iptables -S output contains
		// no quoted strings or special characters that would affect parsing
		args = append(args, strings.Fields(rule)...)
		cmd := safeCommand(cmdPath("iptables"), args...)
		_ = cmd.Run()
	}
}

// flushInputRules removes all INPUT ACCEPT rules for dnsfilter ports on a bridge.
// See flushNATRules for security analysis of iptables output parsing.
func (s *PrivilegeServer) flushInputRules(bridge string) {
	listCmd := safeCommand(cmdPath("iptables"), "-w", "-S", "INPUT")
	output, err := listCmd.Output()
	if err != nil {
		return
	}

	var rulesToDelete []string
	for line := range strings.SplitSeq(string(output), "\n") {
		// Match rules like: -A INPUT -i ab-xxx -p udp -m udp --dport 34711 -j ACCEPT
		// We identify abox filter INPUT rules by: bridge interface + ACCEPT + port in
		// the abox service range (5353-65535). This avoids accidentally deleting
		// user-added firewall rules for well-known ports.
		if !strings.Contains(line, "-i "+bridge) ||
			!strings.Contains(line, "-j ACCEPT") {
			continue
		}
		port := extractDportFromRule(line)
		if port < 5353 {
			continue
		}
		rulesToDelete = append(rulesToDelete, line)
		if len(rulesToDelete) >= maxFlushRules {
			logging.Audit("privilege-helper.flush", "warning", "excessive INPUT rules for bridge, truncating", "bridge", bridge, "limit", maxFlushRules)
			break
		}
	}

	for i := len(rulesToDelete) - 1; i >= 0; i-- {
		rule := rulesToDelete[i]
		rule = strings.TrimPrefix(rule, "-A ")
		args := []string{"-w", "-D"}
		args = append(args, strings.Fields(rule)...)
		cmd := safeCommand(cmdPath("iptables"), args...)
		_ = cmd.Run()
	}
}

// extractDportFromRule extracts the --dport value from an iptables -S output line.
// Returns 0 if no valid port is found.
func extractDportFromRule(line string) int {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "--dport" && i+1 < len(fields) {
			port, err := strconv.Atoi(fields[i+1])
			if err == nil && port > 0 && port <= 65535 {
				return port
			}
		}
	}
	return 0
}

// validateCopySource validates source paths for copy operations.
// Only allows the connecting user's abox directory to prevent world-writable
// temp directories from being used as sources (which could allow any user to
// inject malicious files).
func (s *PrivilegeServer) validateCopySource(path string) error {
	if err := ValidateArgs([]string{path}); err != nil {
		return err
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed in source: %s", path)
	}

	// Allow .qcow2 disk images and .iso cloud-init images
	if !strings.HasSuffix(path, ".qcow2") && !strings.HasSuffix(path, ".iso") {
		return fmt.Errorf("source must be .qcow2 or .iso file: %s", path)
	}

	cleanPath := filepath.Clean(path)

	// Only allow user-private directories - NOT world-writable temp directories
	// This prevents attacks where any user could place malicious files in /tmp
	if s.isAllowedHomePath(cleanPath) {
		return nil
	}
	if s.isAllowedRunPath(cleanPath) {
		return nil
	}

	return fmt.Errorf("source path not in allowed directories: %s", path)
}

// isAllowedHomePath checks whether cleanPath is under /home/<user>/.local/share/abox/{base,instances}/
// and that the home directory is owned by the allowed UID.
//
// Note: We can't use os.UserHomeDir() because the helper runs as root,
// so it would return /root instead of the actual user's home directory.
// Instead, we check for the pattern /home/*/.local/share/abox/
//
// Known limitation: only /home/<user>/... paths are supported. Non-standard
// home directories (e.g., /Users on macOS, or custom locations) would require
// passing the user's home dir from the client and validating ownership.
func (s *PrivilegeServer) isAllowedHomePath(cleanPath string) bool {
	if !strings.HasPrefix(cleanPath, "/home/") {
		return false
	}
	// Extract path after /home/<user>/
	parts := strings.SplitN(cleanPath, "/", 4) // ["", "home", "user", "rest..."]
	if len(parts) < 4 {
		return false
	}
	homeDir := "/" + parts[1] + "/" + parts[2]
	if err := s.verifyDirOwnership(homeDir); err != nil {
		return false
	}
	rest := "/" + parts[3] // e.g., ".local/share/abox/base/file.qcow2"
	return strings.HasPrefix(rest, "/.local/share/abox/base/") ||
		strings.HasPrefix(rest, "/.local/share/abox/instances/")
}

// isAllowedRunPath checks whether cleanPath is under /run/user/<allowedUID>/
// and that the runtime directory is owned by the allowed UID.
func (s *PrivilegeServer) isAllowedRunPath(cleanPath string) bool {
	expectedRunDir := fmt.Sprintf("/run/user/%d", s.allowedUID)
	if !strings.HasPrefix(cleanPath, expectedRunDir+"/") {
		return false
	}
	return s.verifyDirOwnership(expectedRunDir) == nil
}

// verifyDirOwnership checks that dir exists and is owned by s.allowedUID.
func (s *PrivilegeServer) verifyDirOwnership(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("cannot verify directory ownership: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(s.allowedUID) { //nolint:gosec // UID is always non-negative
		return fmt.Errorf("directory %s not owned by allowed UID %d", dir, s.allowedUID)
	}
	return nil
}
