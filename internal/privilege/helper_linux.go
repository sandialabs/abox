//go:build linux

package privilege

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
)

// resolvePlatformCommands resolves the absolute path to iptables (the only
// external command the Linux egress helper invokes). Idempotent.
func resolvePlatformCommands() error {
	iptablesMu.Lock()
	defer iptablesMu.Unlock()

	if iptablesAbs != "" {
		return nil
	}

	path, err := exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("required command %q not found in PATH: %w", "iptables", err)
	}
	// Use absolute path but do NOT resolve symlinks. iptables is a multi-call
	// binary (xtables-nft-multi) that uses argv[0] to determine behavior;
	// resolving symlinks breaks it.
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for iptables: %w", err)
	}
	iptablesAbs = abs
	return nil
}

// registerHelperServices registers the Linux privileged services with the gRPC
// server. On Linux the helper enforces egress via iptables (the Egress service).
func registerHelperServices(server *grpc.Server, allowedUID int) {
	rpc.RegisterEgressServer(server, &EgressServer{allowedUID: allowedUID})
}
