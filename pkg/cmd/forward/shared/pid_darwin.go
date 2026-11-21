//go:build darwin

package shared

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// FindPIDByPattern returns the PID of a process whose command line matches
// every given pattern. The first pattern goes through `pgrep -f` (macOS has no
// /proc, so the Linux cmdline scan is unavailable; pgrep matches against the
// full argument list the same way); candidates are then filtered against the
// remaining patterns via `ps`. The SSH tunnel is started with `ssh -f`
// (self-backgrounding), so its PID is not the child abox launched — this lookup
// recovers it by its -L/-R forward argument (e.g. "localhost:8080:localhost:80")
// plus the instance's user@ip target.
func FindPIDByPattern(patterns ...string) (int, error) {
	joined := strings.Join(patterns, " ")
	out, err := exec.Command("pgrep", "-f", patterns[0]).Output()
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		// pgrep exits 1 with no output when there are no matches; report the
		// same not-found error the /proc scan does so WaitForSSHProcess keeps
		// polling rather than aborting.
		if trimmed == "" {
			return 0, fmt.Errorf("no process found matching pattern: %s", joined)
		}
		return 0, fmt.Errorf("pgrep failed: %w", err)
	}

	// Return the first valid PID that also matches the remaining patterns.
	for line := range strings.FieldsSeq(trimmed) {
		pid, perr := strconv.Atoi(line)
		if perr != nil || pid <= 0 {
			continue
		}
		if len(patterns) > 1 && !processMatchesAll(pid, patterns[1:]) {
			continue
		}
		return pid, nil
	}

	return 0, fmt.Errorf("no process found matching pattern: %s", joined)
}

// processMatchesAll fetches pid's full command line via ps and reports whether
// it contains every pattern (pgrep -f only matched the first). A vanished or
// unreadable process does not match.
func processMatchesAll(pid int, patterns []string) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false
	}
	return matchesAll(string(out), patterns)
}
