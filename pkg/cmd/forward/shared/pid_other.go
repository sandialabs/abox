//go:build !linux && !darwin

package shared

import (
	"fmt"
	"runtime"
)

// FindPIDByPattern is unsupported on platforms with neither /proc nor pgrep
// (currently Windows). Port forwarding has no VM backend to target there yet,
// so this returns a clear error rather than a silent no-match.
func FindPIDByPattern(pattern string) (int, error) {
	return 0, fmt.Errorf("finding processes by command-line pattern is not supported on %s", runtime.GOOS)
}
