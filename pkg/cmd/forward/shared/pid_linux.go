//go:build linux

package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FindPIDByPattern scans /proc/*/cmdline for a process matching the given pattern.
func FindPIDByPattern(pattern string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		// No /proc/[pid]/exe check: this function finds SSH tunnel processes
		// (not abox processes), so the exe is /usr/bin/ssh, not our binary.
		// The cmdline pattern (e.g. "localhost:8080:localhost:80") is specific
		// enough to avoid false matches.
		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue // Process may have exited
		}

		// cmdline uses null bytes as separators
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		if strings.Contains(cmdline, pattern) {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("no process found matching pattern: %s", pattern)
}
