//go:build !linux && !darwin

package daemon

import (
	"fmt"
	"runtime"
)

// isAboxProcess cannot verify a PID's executable on platforms without /proc
// (Linux) or `ps -o comm=` semantics (darwin). Per the IsAboxProcess contract it
// returns (false, err) — "unverifiable" — which the caller maps to false, so no
// process is ever signaled on the strength of an unconfirmed identity. abox
// daemons are not supported off Linux/darwin; this seam exists so the tree
// cross-compiles.
func isAboxProcess(_ int) (bool, error) {
	return false, fmt.Errorf("process verification is not supported on %s", runtime.GOOS)
}
