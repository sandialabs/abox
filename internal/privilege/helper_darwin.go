//go:build darwin

package privilege

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// PrivilegeServer implements the gRPC Privilege service on macOS.
type PrivilegeServer struct {
	rpc.UnimplementedPrivilegeServer
	allowedUID int
}

// ResolveCommands resolves absolute paths for all external commands used
// by the macOS privilege helper.
func ResolveCommands() error {
	return resolveCommandList([]struct {
		name     string
		required bool
	}{
		{"pfctl", true},
		{"qemu-img", true},
	})
}

// RegisterServer registers the macOS PrivilegeServer with the gRPC server.
func RegisterServer(server *grpc.Server, allowedUID int) {
	rpc.RegisterPrivilegeServer(server, &PrivilegeServer{allowedUID: allowedUID})
}

// Ping handles the ping operation (health check).
func (s *PrivilegeServer) Ping(_ context.Context, _ *rpc.Empty) (*rpc.StringMsg, error) {
	return &rpc.StringMsg{Message: "pong"}, nil
}

// Shutdown gracefully terminates the helper process.
func (s *PrivilegeServer) Shutdown(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	gracefulShutdown()
	return &rpc.Empty{}, nil
}

// QemuImgCreate creates a qemu disk image.
// On macOS, storage is user-owned so symlink/TOCTOU protections are less critical
// than on Linux (where storage is root-owned). Basic validation is still applied.
func (s *PrivilegeServer) QemuImgCreate(_ context.Context, req *rpc.QemuImgReq) (*rpc.Empty, error) {
	if !strings.HasSuffix(req.Output, ".qcow2") {
		return nil, fmt.Errorf("output must end with .qcow2: %s", req.Output)
	}

	if req.BackingFile != "" {
		if !strings.HasSuffix(req.BackingFile, ".qcow2") {
			return nil, fmt.Errorf("backing file must be .qcow2: %s", req.BackingFile)
		}
		if strings.Contains(req.BackingFile, "..") {
			return nil, fmt.Errorf("path traversal not allowed in backing file: %s", req.BackingFile)
		}
	}

	if err := validateDiskSize(req.Size); err != nil {
		return nil, err
	}

	args := []string{"create", "-f", "qcow2"}
	if req.BackingFile != "" {
		args = append(args, "-F", "qcow2", "-b", req.BackingFile)
	}
	args = append(args, req.Output, req.Size)

	cmd := safeCommand(cmdPath("qemu-img"), args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("qemu-img create failed: %s: %w", string(output), err)
	}

	return &rpc.Empty{}, nil
}

// Chmod changes file permissions.
func (s *PrivilegeServer) Chmod(_ context.Context, req *rpc.ChmodReq) (*rpc.Empty, error) {
	if err := ValidateChmodMode(req.Mode); err != nil {
		return nil, err
	}

	if err := ValidateArgs([]string{req.Path}); err != nil {
		return nil, err
	}

	mode, err := os.Stat(req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat: %w", err)
	}
	_ = mode

	parsed, err := parseOctalMode(req.Mode)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(req.Path, parsed); err != nil {
		return nil, fmt.Errorf("failed to chmod: %w", err)
	}

	return &rpc.Empty{}, nil
}

// MkdirAll creates directories.
func (s *PrivilegeServer) MkdirAll(_ context.Context, req *rpc.MkdirReq) (*rpc.Empty, error) {
	if err := ValidateArgs([]string{req.Path}); err != nil {
		return nil, err
	}

	if err := ValidateChmodMode(req.Mode); err != nil {
		return nil, err
	}

	parsed, err := parseOctalMode(req.Mode)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(req.Path, parsed); err != nil {
		return nil, fmt.Errorf("failed to mkdir: %w", err)
	}

	return &rpc.Empty{}, nil
}

// RemoveAll removes a directory tree.
func (s *PrivilegeServer) RemoveAll(_ context.Context, req *rpc.PathReq) (*rpc.Empty, error) {
	if err := ValidateArgs([]string{req.Path}); err != nil {
		return nil, err
	}

	if strings.Contains(req.Path, "..") {
		return nil, fmt.Errorf("path traversal not allowed: %s", req.Path)
	}

	if err := os.RemoveAll(req.Path); err != nil {
		return nil, fmt.Errorf("failed to remove: %w", err)
	}

	return &rpc.Empty{}, nil
}

// CopyFile copies a file.
func (s *PrivilegeServer) CopyFile(_ context.Context, req *rpc.CopyReq) (*rpc.Empty, error) {
	if err := ValidateArgs([]string{req.Src, req.Dst}); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(req.Src)
	if err != nil {
		return nil, fmt.Errorf("failed to read source: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(req.Dst), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create destination directory: %w", err)
	}

	if err := os.WriteFile(req.Dst, data, 0o600); err != nil { //nolint:gosec // path validated via ValidateArgs
		return nil, fmt.Errorf("failed to write destination: %w", err)
	}

	return &rpc.Empty{}, nil
}

// PfctlEnable enables the PF firewall.
func (s *PrivilegeServer) PfctlEnable(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	cmd := safeCommand(cmdPath("pfctl"), "-e")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// pfctl -e exits non-zero when PF is already enabled on some macOS versions.
		if strings.Contains(string(output), "already enabled") {
			return &rpc.Empty{}, nil
		}
		return nil, fmt.Errorf("failed to enable PF: %s: %w", string(output), err)
	}
	return &rpc.Empty{}, nil
}

// PfctlLoadAnchor loads PF rules into an instance-specific anchor.
func (s *PrivilegeServer) PfctlLoadAnchor(_ context.Context, req *rpc.PfctlAnchorReq) (*rpc.Empty, error) {
	if err := validateInstanceName(req.InstanceName); err != nil {
		return nil, err
	}

	if req.RulesContent == "" {
		return nil, errors.New("rules content is required")
	}

	// Write rules to a temp file
	runtimeDir := config.RuntimeDirOr(os.TempDir())
	rulesFile := filepath.Join(runtimeDir, fmt.Sprintf("abox-%s-pf.conf", req.InstanceName))

	if err := os.WriteFile(rulesFile, []byte(req.RulesContent), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write PF rules file: %w", err)
	}
	defer os.Remove(rulesFile)

	anchor := "abox/" + req.InstanceName
	cmd := safeCommand(cmdPath("pfctl"), "-a", anchor, "-f", rulesFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to load PF rules: %s: %w", string(output), err)
	}

	logging.Audit("pfctl anchor loaded",
		"action", logging.ActionPfctlAddDNS,
		"instance", req.InstanceName,
	)

	return &rpc.Empty{}, nil
}

// PfctlFlushAnchor removes all PF rules from an instance-specific anchor.
func (s *PrivilegeServer) PfctlFlushAnchor(_ context.Context, req *rpc.PfctlAnchorReq) (*rpc.Empty, error) {
	if err := validateInstanceName(req.InstanceName); err != nil {
		return nil, err
	}

	anchor := "abox/" + req.InstanceName
	cmd := safeCommand(cmdPath("pfctl"), "-a", anchor, "-F", "all")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to flush PF anchor: %s: %w", string(output), err)
	}

	logging.Audit("pfctl anchor flushed",
		"action", logging.ActionPfctlFlushDNS,
		"instance", req.InstanceName,
	)

	return &rpc.Empty{}, nil
}

// validateInstanceName validates an instance name for use in PF anchors.
func validateInstanceName(name string) error {
	if name == "" {
		return errors.New("instance name is required")
	}
	if len(name) > 63 {
		return fmt.Errorf("instance name exceeds 63 characters: %s", name)
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("invalid instance name %q: contains unsafe character %q", name, c)
		}
	}
	return nil
}

// parseOctalMode parses a string octal mode into os.FileMode.
func parseOctalMode(mode string) (os.FileMode, error) {
	m, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid mode %q: %w", mode, err)
	}
	return os.FileMode(m), nil
}
