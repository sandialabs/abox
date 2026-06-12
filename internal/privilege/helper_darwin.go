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
// On macOS, storage is user-owned so symlink/TOCTOU *pinning* is dropped
// relative to Linux (where storage is root-owned). Path *containment* is kept:
// both the output and any backing file are confined to the per-user abox
// storage root, mirroring helper_linux.go's QemuImgCreate/validateBackingFile.
func (s *PrivilegeServer) QemuImgCreate(_ context.Context, req *rpc.QemuImgReq) (*rpc.Empty, error) {
	if !strings.HasSuffix(req.Output, ".qcow2") {
		return nil, fmt.Errorf("output must end with .qcow2: %s", req.Output)
	}
	if err := s.ValidatePathNoSymlinks(req.Output); err != nil {
		return nil, err
	}

	if req.BackingFile != "" {
		if !strings.HasSuffix(req.BackingFile, ".qcow2") {
			return nil, fmt.Errorf("backing file must be .qcow2: %s", req.BackingFile)
		}
		if err := s.ValidatePathNoSymlinks(req.BackingFile); err != nil {
			return nil, err
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
// Path is confined to the per-user abox storage root (no-symlinks variant).
// Like Linux, the mode itself is not restricted — confining the path is what
// contains the root-privileged surface (setuid-bit chmod outside abox storage
// is what an attacker would want, and the path check already blocks that).
func (s *PrivilegeServer) Chmod(_ context.Context, req *rpc.ChmodReq) (*rpc.Empty, error) {
	if err := ValidateChmodMode(req.Mode); err != nil {
		return nil, err
	}

	if err := s.ValidatePathNoSymlinks(req.Path); err != nil {
		return nil, err
	}

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
// Path is confined to the per-user abox storage root (no-symlinks variant).
func (s *PrivilegeServer) MkdirAll(_ context.Context, req *rpc.MkdirReq) (*rpc.Empty, error) {
	if err := s.ValidatePathNoSymlinks(req.Path); err != nil {
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
// Confined to the per-user abox storage root with a minimum-depth guard so the
// root itself (or an ancestor) can never be removed. Mirrors Linux RemoveAll.
func (s *PrivilegeServer) RemoveAll(_ context.Context, req *rpc.PathReq) (*rpc.Empty, error) {
	if err := s.ValidateRemoveAllPath(req.Path); err != nil {
		return nil, err
	}

	if err := s.ValidatePathNoSymlinks(req.Path); err != nil {
		return nil, err
	}

	if err := os.RemoveAll(req.Path); err != nil {
		return nil, fmt.Errorf("failed to remove: %w", err)
	}

	return &rpc.Empty{}, nil
}

// CopyFile copies a file.
// Both src and dst are confined to the per-user abox storage root. Mirroring
// helper_linux.go's validateCopySource spirit, the source must be an abox disk
// or ISO image (.qcow2/.iso); the destination is confined with the no-symlinks
// variant.
func (s *PrivilegeServer) CopyFile(_ context.Context, req *rpc.CopyReq) (*rpc.Empty, error) {
	if !strings.HasSuffix(req.Src, ".qcow2") && !strings.HasSuffix(req.Src, ".iso") {
		return nil, fmt.Errorf("source must be .qcow2 or .iso file: %s", req.Src)
	}
	if err := s.ValidatePathNoSymlinks(req.Src); err != nil {
		return nil, err
	}
	if err := s.ValidatePathNoSymlinks(req.Dst); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(req.Src)
	if err != nil {
		return nil, fmt.Errorf("failed to read source: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(req.Dst), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create destination directory: %w", err)
	}

	if err := os.WriteFile(req.Dst, data, 0o600); err != nil { //nolint:gosec // path confined via ValidatePathNoSymlinks
		return nil, fmt.Errorf("failed to write destination: %w", err)
	}

	return &rpc.Empty{}, nil
}

// PfctlEnable enables the PF firewall and ensures /etc/pf.conf references the
// abox/* anchors so per-instance sub-anchor rules are evaluated by the kernel.
//
// On first run after install, /etc/pf.conf is updated atomically (one rdr
// reference in the translation section, one anchor reference in the filter
// section, each placed adjacent to the corresponding com.apple/* sibling)
// and the main ruleset is reloaded. Subsequent calls detect the existing
// references and no-op.
func (s *PrivilegeServer) PfctlEnable(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	changed, err := ensureAnchorReferences(PfconfDefaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to wire PF anchor references: %w", err)
	}
	if changed {
		if err := reloadPfConf(); err != nil {
			// Roll back the file edit so the user isn't left with a pf.conf
			// referencing anchors that the kernel rejected for unrelated
			// reasons. Surface both errors if rollback itself fails — silent
			// rollback failure would leave pf.conf in an unknown state.
			if _, rmErr := removeAnchorReferences(PfconfDefaultPath); rmErr != nil {
				logging.Audit("PF rollback failed",
					"action", logging.ActionPfctlWireAnchors,
					"error", rmErr.Error(),
				)
				return nil, fmt.Errorf(
					"pfctl -f %s failed after wiring anchors: %w "+
						"(rollback also failed: %v — pf.conf may be left "+
						"with abox references; run `abox teardown-pf` to clean up)",
					PfconfDefaultPath, err, rmErr)
			}
			return nil, fmt.Errorf("pfctl -f %s failed after wiring anchors: %w",
				PfconfDefaultPath, err)
		}
		logging.Audit("PF anchor references wired into /etc/pf.conf",
			"action", logging.ActionPfctlWireAnchors,
		)
	}

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

// PfctlTeardownConfig removes the abox-managed anchor references from
// /etc/pf.conf and reloads the main ruleset. Used by `abox teardown-pf`.
func (s *PrivilegeServer) PfctlTeardownConfig(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	changed, err := removeAnchorReferences(PfconfDefaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to remove PF anchor references: %w", err)
	}
	if !changed {
		return &rpc.Empty{}, nil
	}

	if err := reloadPfConf(); err != nil {
		return nil, fmt.Errorf("pfctl -f %s failed after removing anchors: %w",
			PfconfDefaultPath, err)
	}

	logging.Audit("PF anchor references removed from /etc/pf.conf",
		"action", logging.ActionPfctlUnwireAnchors,
	)
	return &rpc.Empty{}, nil
}

// reloadPfConf reloads the main PF ruleset from /etc/pf.conf.
func reloadPfConf() error {
	cmd := safeCommand(cmdPath("pfctl"), "-f", PfconfDefaultPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
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
