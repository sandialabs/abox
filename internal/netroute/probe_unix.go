//go:build darwin || linux

package netroute

import (
	"context"
	"os/exec"
	"time"
)

// probeTimeout bounds each host-route probe. It runs inline during subnet
// allocation and is fail-open, so a short timeout simply means "no conflict".
const probeTimeout = 2 * time.Second

// runProbe executes a read-only route-query command with a bounded context and
// returns its combined output. It is a package var so tests can stub it without
// shelling out. A non-nil error (including a timeout) makes SubnetRouted fail open.
var runProbe = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
