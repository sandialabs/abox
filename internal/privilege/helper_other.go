//go:build !linux && !darwin

package privilege

import (
	"errors"
	"runtime"

	"google.golang.org/grpc"
)

// resolvePlatformCommands fails closed on platforms other than Linux/darwin. The
// privileged egress helper enforces isolation via iptables (Linux) or pfctl
// (darwin); neither exists here, so the helper must refuse to start rather than
// come up without any enforcement mechanism.
func resolvePlatformCommands() error {
	return errors.New("privilege helper is not supported on " + runtime.GOOS)
}

// registerHelperServices registers no privileged services on unsupported
// platforms. It is unreachable in practice because resolvePlatformCommands fails
// first; it exists to satisfy the ResolveCommands/Serve seam so the tree
// cross-compiles.
func registerHelperServices(_ *grpc.Server, _ int) {}
