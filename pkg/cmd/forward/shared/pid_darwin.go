//go:build darwin

package shared

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// FindPIDByPattern returns the PID of a process whose command line matches the
// given pattern, using `pgrep -f`. macOS has no /proc, so the Linux cmdline scan
// is unavailable; pgrep matches against the full argument list the same way.
// The SSH tunnel is started with `ssh -f` (self-backgrounding), so its PID is
// not the child abox launched — this lookup recovers it by its unique -L/-R
// forward argument (e.g. "localhost:8080:localhost:80").
func FindPIDByPattern(pattern string) (int, error) {
	out, err := exec.Command("pgrep", "-f", pattern).Output()
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		// pgrep exits 1 with no output when there are no matches; report the
		// same not-found error the /proc scan does so WaitForSSHProcess keeps
		// polling rather than aborting.
		if trimmed == "" {
			return 0, fmt.Errorf("no process found matching pattern: %s", pattern)
		}
		return 0, fmt.Errorf("pgrep failed: %w", err)
	}

	// Return the first valid PID. The forward argument is unique per host port,
	// so at most one SSH tunnel matches in practice.
	for line := range strings.FieldsSeq(trimmed) {
		if pid, perr := strconv.Atoi(line); perr == nil && pid > 0 {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("no process found matching pattern: %s", pattern)
}
