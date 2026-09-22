//go:build darwin

package privilege

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// pfctlPath is the absolute path to pfctl. macOS ships it at /sbin/pfctl and the
// helper always runs as root (via sudo), so an absolute path is used directly
// (defense-in-depth against PATH manipulation) rather than resolved via
// exec.LookPath.
const pfctlPath = "/sbin/pfctl"

// resolvePlatformCommands is a no-op on darwin: pfctl is invoked at its fixed
// absolute path (pfctlPath). Kept to satisfy the ResolveCommands seam.
func resolvePlatformCommands() error {
	return nil
}

// registerHelperServices registers the darwin privileged services with the gRPC
// server. On darwin the helper enforces egress via pfctl (the Pf service).
func registerHelperServices(server *grpc.Server, allowedUID int) {
	rpc.RegisterPfServer(server, newPfServer(allowedUID))
}

// PfServer implements the gRPC Pf service on macOS. It loads per-instance
// egress rules into the abox/<instance> pf anchor. Rules key on the instance's
// deterministic /24 subnet (passed in the request and independently enforced by
// validatePFRules), not the VM's DHCP IP, because the generic egress lifecycle
// applies rules before the guest has a lease.
type PfServer struct {
	rpc.UnimplementedPfServer
	allowedUID int
}

// newPfServer constructs a PfServer for the given allowed client UID.
func newPfServer(allowedUID int) *PfServer {
	return &PfServer{allowedUID: allowedUID}
}

// Ping handles the health-check RPC.
func (s *PfServer) Ping(_ context.Context, _ *rpc.Empty) (*rpc.StringMsg, error) {
	return pingReply(), nil
}

// Shutdown gracefully terminates the helper process. Mirrors the Egress
// server's Shutdown: GracefulStop lets server.Serve() in RunHelper return so
// deferred socket cleanup runs.
func (s *PfServer) Shutdown(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	shutdownServerAsync()
	return &rpc.Empty{}, nil
}

// Enable turns on pf (if needed) and wires the abox/* anchor references into
// /etc/pf.conf so the kernel descends into the per-instance sub-anchors.
//
// On first run /etc/pf.conf is updated atomically (one rdr reference in the
// translation section, one anchor reference in the filter section, each placed
// adjacent to the corresponding com.apple/* Apple marker) and the main ruleset
// is reloaded. Subsequent calls detect the existing references and no-op. If the
// Apple markers are absent, the file is left untouched and a clear error is
// returned (see ensureAnchorReferences).
func (s *PfServer) Enable(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
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
						"with abox references)",
					PfconfDefaultPath, err, rmErr)
			}
			return nil, fmt.Errorf("pfctl -f %s failed after wiring anchors: %w",
				PfconfDefaultPath, err)
		}
		logging.Audit("PF anchor references wired into /etc/pf.conf",
			"action", logging.ActionPfctlWireAnchors,
		)
	}

	cmd, err := safeCommand("-e")
	if err != nil {
		return nil, err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		// pfctl -e exits non-zero when pf is already enabled on some macOS
		// versions; treat that as success (idempotent).
		if strings.Contains(string(output), "already enabled") {
			return &rpc.Empty{}, nil
		}
		return nil, fmt.Errorf("failed to enable PF: %s: %w", string(output), err)
	}
	return &rpc.Empty{}, nil
}

// LoadAnchor validates the request and loads the per-instance rules into the
// abox/<instance> anchor. The rules are fed to pfctl on STDIN (`-f -`) rather
// than via a temp file, which avoids any predictable-path / symlink race on the
// rules file. All three request fields are re-validated server-side because
// client-side validation is not a trust boundary: a token-holding caller could
// otherwise load arbitrary pf text or rules keyed on another instance's subnet.
func (s *PfServer) LoadAnchor(_ context.Context, req *rpc.PfAnchorReq) (*rpc.Empty, error) {
	if err := validateInstanceName(req.GetInstance()); err != nil {
		return nil, err
	}
	// validatePFRules validates the subnet (valid /24 CIDR) and binds every rule
	// token to it, so no separate subnet check is needed beyond this call.
	if err := validatePFRules(req.GetRules(), req.GetSubnet()); err != nil {
		return nil, fmt.Errorf("invalid PF rules: %w", err)
	}

	anchor := "abox/" + req.GetInstance()
	cmd, err := safeCommand("-a", anchor, "-f", "-")
	if err != nil {
		return nil, err
	}
	cmd.Stdin = strings.NewReader(req.GetRules())
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to load PF rules: %s: %w", out.String(), err)
	}

	logging.Audit("pfctl anchor loaded",
		"action", logging.ActionPfctlLoadAnchor,
		"instance", req.GetInstance(),
	)

	return &rpc.Empty{}, nil
}

// FlushAnchor removes all rules from the abox/<instance> anchor (idempotent).
func (s *PfServer) FlushAnchor(_ context.Context, req *rpc.PfInstanceReq) (*rpc.Empty, error) {
	if err := validateInstanceName(req.GetInstance()); err != nil {
		return nil, err
	}

	anchor := "abox/" + req.GetInstance()
	cmd, err := safeCommand("-a", anchor, "-F", "all")
	if err != nil {
		return nil, err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to flush PF anchor: %s: %w", string(output), err)
	}

	logging.Audit("pfctl anchor flushed",
		"action", logging.ActionPfctlFlushAnchor,
		"instance", req.GetInstance(),
	)

	return &rpc.Empty{}, nil
}

// TeardownConfig removes the abox-managed anchor references from /etc/pf.conf
// and reloads the main ruleset.
func (s *PfServer) TeardownConfig(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	changed, err := removeAnchorReferences(PfconfDefaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to remove PF anchor references: %w", err)
	}
	if !changed {
		return &rpc.Empty{}, nil
	}

	// The file edit has already landed, so audit it before attempting the
	// reload: the references are gone from pf.conf whether or not the kernel
	// accepts the new main ruleset, and the audit trail must reflect that.
	logging.Audit("PF anchor references removed from /etc/pf.conf",
		"action", logging.ActionPfctlTeardown,
	)

	if err := reloadPfConf(); err != nil {
		// A pf.conf that was already unparseable (e.g. an unterminated final
		// statement from some other tool) fails to reload no matter what we
		// remove. Say plainly that the removal succeeded so the user doesn't
		// re-run teardown chasing a failure that isn't abox's to fix.
		return nil, fmt.Errorf(
			"abox anchor references were removed from %s, but reloading the "+
				"main ruleset failed — pf.conf has a problem unrelated to those "+
				"references and is likely also failing to load at boot: %w",
			PfconfDefaultPath, err)
	}

	logging.Audit("PF main ruleset reloaded after teardown",
		"action", logging.ActionPfctlTeardown,
	)
	return &rpc.Empty{}, nil
}

// reloadPfConf reloads the main PF ruleset from /etc/pf.conf.
func reloadPfConf() error {
	cmd, err := safeCommand("-f", PfconfDefaultPath)
	if err != nil {
		return err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
