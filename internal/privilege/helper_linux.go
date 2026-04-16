//go:build linux

package privilege

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// PrivilegeServer implements the gRPC Privilege service on Linux.
type PrivilegeServer struct {
	rpc.UnimplementedPrivilegeServer
	allowedUID int
}

// ResolveCommands resolves absolute paths for all external commands used
// by the Linux privilege helper. This should be called once at startup.
// In setuid context, PATH is sanitized but absolute paths provide defense-in-depth.
func ResolveCommands() error {
	return resolveCommandList([]struct {
		name     string
		required bool
	}{
		{"iptables", true},
		{"qemu-img", true},
		{"chmod", true},
		{"ufw", false}, // Optional: not all systems use ufw
	})
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

// RegisterServer registers the Linux PrivilegeServer with the gRPC server.
func RegisterServer(server *grpc.Server, allowedUID int) {
	rpc.RegisterPrivilegeServer(server, &PrivilegeServer{allowedUID: allowedUID})
}

// Ping handles the ping operation (health check).
func (s *PrivilegeServer) Ping(_ context.Context, _ *rpc.Empty) (*rpc.StringMsg, error) {
	return &rpc.StringMsg{Message: "pong"}, nil
}

// Shutdown gracefully terminates the helper process.
// GracefulStop causes server.Serve() to return, which lets deferred cleanup
// (socket removal) in RunHelper execute naturally.
func (s *PrivilegeServer) Shutdown(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	gracefulShutdown()
	return &rpc.Empty{}, nil
}

// QemuImgCreate creates a qemu disk image.
//
// Note: The output path has a TOCTOU window between ValidatePathNoSymlinks and
// the qemu-img exec (which takes a string path). The backing file is resolved
// via O_NOFOLLOW + /proc/self/fd (TOCTOU-safe). For the output path, there is no
// fd-based alternative since qemu-img requires a filename argument. Security
// relies on the parent directory being root-owned — see MkdirAll comment.
func (s *PrivilegeServer) QemuImgCreate(_ context.Context, req *rpc.QemuImgReq) (*rpc.Empty, error) {
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
func (s *PrivilegeServer) Chmod(_ context.Context, req *rpc.ChmodReq) (*rpc.Empty, error) {
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
func (s *PrivilegeServer) MkdirAll(_ context.Context, req *rpc.MkdirReq) (*rpc.Empty, error) {
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
func (s *PrivilegeServer) RemoveAll(_ context.Context, req *rpc.PathReq) (*rpc.Empty, error) {
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
func (s *PrivilegeServer) CopyFile(_ context.Context, req *rpc.CopyReq) (*rpc.Empty, error) {
	if err := ValidatePathNoSymlinks(req.Dst); err != nil {
		return nil, err
	}

	if err := s.validateCopySource(req.Src); err != nil {
		return nil, err
	}

	// Open source with O_NOFOLLOW to prevent symlink TOCTOU attacks.
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

	err = dstFile.Close()
	dstFile = nil
	if err != nil {
		return nil, fmt.Errorf("failed to flush destination file: %w", err)
	}

	return &rpc.Empty{}, nil
}

// UfwStatus checks if UFW is installed and active.
func (s *PrivilegeServer) UfwStatus(_ context.Context, _ *rpc.Empty) (*rpc.UfwStatusResp, error) {
	resp := &rpc.UfwStatusResp{}

	if !cmdResolved("ufw") {
		path, err := exec.LookPath("ufw")
		if err != nil {
			return resp, nil //nolint:nilerr // ufw not installed is a valid status, not an error
		}
		abs, err := filepath.EvalSymlinks(path)
		if err != nil {
			return resp, nil //nolint:nilerr // can't resolve path; treat as not installed
		}
		setCmdPath("ufw", abs)
	}
	ufwPath := cmdPath("ufw")
	resp.Installed = true

	cmd := safeCommand(ufwPath, "status")
	output, err := cmd.Output()
	if err != nil {
		return resp, nil //nolint:nilerr // can't query ufw status; assume inactive
	}
	resp.Active = strings.Contains(string(output), "Status: active")

	return resp, nil
}

// UfwAdd adds an allow rule for traffic on a bridge interface.
func (s *PrivilegeServer) UfwAdd(_ context.Context, req *rpc.UfwReq) (*rpc.Empty, error) {
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
func (s *PrivilegeServer) UfwRemove(_ context.Context, req *rpc.UfwReq) (*rpc.Empty, error) {
	if err := ValidateBridgeName(req.Bridge); err != nil {
		return nil, err
	}

	cmd := safeCommand(cmdPath("ufw"), "delete", "allow", "in", "on", req.Bridge)
	output, err := cmd.CombinedOutput()
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
func (s *PrivilegeServer) IptablesAdd(_ context.Context, req *rpc.IptablesReq) (*rpc.Empty, error) {
	portStr, err := validateIptablesReq(req)
	if err != nil {
		return nil, err
	}

	cmd := safeCommand(cmdPath("iptables"),
		"-w",
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

	inputCmd := safeCommand(cmdPath("iptables"),
		"-w",
		"-I", "INPUT",
		"-i", req.Bridge,
		"-p", req.Protocol,
		"--dport", portStr,
		"-j", "ACCEPT",
	)
	inputOutput, err := inputCmd.CombinedOutput()
	if err != nil {
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
func (s *PrivilegeServer) IptablesRemove(_ context.Context, req *rpc.IptablesReq) (*rpc.Empty, error) {
	portStr, err := validateIptablesReq(req)
	if err != nil {
		return nil, err
	}

	cmd := safeCommand(cmdPath("iptables"),
		"-w",
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

	inputCmd := safeCommand(cmdPath("iptables"),
		"-w",
		"-D", "INPUT",
		"-i", req.Bridge,
		"-p", req.Protocol,
		"--dport", portStr,
		"-j", "ACCEPT",
	)
	_ = inputCmd.Run()

	return &rpc.Empty{}, nil
}

// IptablesFlush removes ALL DNS redirect rules for a bridge interface.
func (s *PrivilegeServer) IptablesFlush(_ context.Context, req *rpc.IptablesFlushReq) (*rpc.Empty, error) {
	if err := ValidateBridgeName(req.Bridge); err != nil {
		return nil, err
	}

	s.flushNATRules(req.Bridge)
	s.flushInputRules(req.Bridge)

	return &rpc.Empty{}, nil
}

// maxFlushRules is the maximum number of iptables rules to delete in a single
// flush operation.
const maxFlushRules = 100

// dnsPort is the standard DNS port that iptables rules redirect from.
const dnsPort = "53"

// flushNATRules removes all NAT PREROUTING REDIRECT rules for a bridge.
func (s *PrivilegeServer) flushNATRules(bridge string) {
	listCmd := safeCommand(cmdPath("iptables"), "-w", "-t", "nat", "-S", "PREROUTING")
	output, err := listCmd.Output()
	if err != nil {
		return
	}

	var rulesToDelete []string
	for line := range strings.SplitSeq(string(output), "\n") {
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
		args = append(args, strings.Fields(rule)...)
		cmd := safeCommand(cmdPath("iptables"), args...)
		_ = cmd.Run()
	}
}

// flushInputRules removes all INPUT ACCEPT rules for dnsfilter ports on a bridge.
func (s *PrivilegeServer) flushInputRules(bridge string) {
	listCmd := safeCommand(cmdPath("iptables"), "-w", "-S", "INPUT")
	output, err := listCmd.Output()
	if err != nil {
		return
	}

	var rulesToDelete []string
	for line := range strings.SplitSeq(string(output), "\n") {
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

// openNoFollow opens a file with O_NOFOLLOW, preventing symlink traversal.
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
func resolvePathNoFollow(path string) (string, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", path)
	}

	fdPath := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	realPath, err := os.Readlink(fdPath)
	if err != nil {
		return "", fmt.Errorf("failed to read fd path: %w", err)
	}

	return realPath, nil
}

// validateBackingFile validates a backing file path for qemu-img.
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
			return ValidatePathNoSymlinks(path)
		}
	}

	return fmt.Errorf("backing file not in allowed paths: %s", path)
}

// validateCopySource validates source paths for copy operations.
func (s *PrivilegeServer) validateCopySource(path string) error {
	if err := ValidateArgs([]string{path}); err != nil {
		return err
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed in source: %s", path)
	}

	if !strings.HasSuffix(path, ".qcow2") && !strings.HasSuffix(path, ".iso") {
		return fmt.Errorf("source must be .qcow2 or .iso file: %s", path)
	}

	cleanPath := filepath.Clean(path)

	if s.isAllowedHomePath(cleanPath) {
		return nil
	}
	if s.isAllowedRunPath(cleanPath) {
		return nil
	}

	return fmt.Errorf("source path not in allowed directories: %s", path)
}

// isAllowedHomePath checks whether cleanPath is under /home/<user>/.local/share/abox/{base,instances}/
func (s *PrivilegeServer) isAllowedHomePath(cleanPath string) bool {
	if !strings.HasPrefix(cleanPath, "/home/") {
		return false
	}
	parts := strings.SplitN(cleanPath, "/", 4)
	if len(parts) < 4 {
		return false
	}
	homeDir := "/" + parts[1] + "/" + parts[2]
	if err := s.verifyDirOwnership(homeDir); err != nil {
		return false
	}
	rest := "/" + parts[3]
	return strings.HasPrefix(rest, "/.local/share/abox/base/") ||
		strings.HasPrefix(rest, "/.local/share/abox/instances/")
}

// isAllowedRunPath checks whether cleanPath is under /run/user/<allowedUID>/
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
