//go:build linux

package privilege

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
)

// resolvePlatformCommands resolves the absolute paths to iptables and ip6tables
// (the external commands the Linux egress helper invokes). Idempotent.
//
// iptables is required. ip6tables is best-effort at resolution time — a host may
// legitimately lack it — but the egress path fails closed at Apply if IPv6 is
// actually enabled on the kernel and ip6tables is missing (see ensureIPv6Denied).
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

	// ip6tables: resolve if present, leave empty otherwise. Same no-symlink-resolve
	// reasoning (ip6tables-nft is also a multi-call binary). Absence is handled at
	// Apply time, not here.
	if p6, err6 := exec.LookPath("ip6tables"); err6 == nil {
		if abs6, aerr := filepath.Abs(p6); aerr == nil {
			ip6tablesAbs = abs6
		}
	}
	return nil
}

// registerHelperServices registers the Linux privileged services with the gRPC
// server. On Linux the helper enforces egress via iptables (the Egress service).
func registerHelperServices(server *grpc.Server, allowedUID int) {
	rpc.RegisterEgressServer(server, &EgressServer{allowedUID: allowedUID})
}
