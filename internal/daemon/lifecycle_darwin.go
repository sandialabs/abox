//go:build darwin

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// procComm returns the executable path of a PID via `ps -p <pid> -o comm=`.
// macOS has no /proc/<pid>/exe, and CGO is disabled (CGO_ENABLED=0) so the
// libproc proc_pidpath() syscall is unavailable; ps is the portable way to
// resolve a PID to its executable path. On macOS the `comm` column is the full
// executable path (e.g. /Users/me/.local/bin/abox), not just the basename.
//
// It is a package variable so tests can substitute a deterministic
// implementation without shelling out, mirroring the lookupComm seam in
// internal/vfkit/process.go.
var procComm = psComm

func psComm(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		// ps exits non-zero when the PID does not exist; surface as an error so
		// the caller can distinguish "gone/unverifiable" from "not abox".
		return "", fmt.Errorf("ps -p %d: %w", pid, err)
	}
	comm := strings.TrimSpace(string(out))
	if comm == "" {
		return "", fmt.Errorf("ps returned no command for pid %d", pid)
	}
	return comm, nil
}

// isAboxProcess verifies a PID belongs to our executable on macOS.
//
// Contract (see IsAboxProcess):
//   - ps error (PID gone, or otherwise unintrospectable) → unverifiable
//     (false, err). Callers must NOT treat this as a confirmed mismatch.
//   - ps ok but path is not our executable → confirmed not-abox (false, nil).
//
// macOS truncates the `comm` column for very long paths, so an exact string
// compare can yield a false mismatch on a legitimately-ours daemon. To stay
// fail-safe (never signal/delete state for a process we cannot positively rule
// out), comparison is tolerant: an exact path match, OR the observed value
// being a non-empty prefix of our executable path AND sharing the same
// basename, both count as "ours". Anything else is a confirmed mismatch.
func isAboxProcess(pid int) (bool, error) {
	comm, err := procComm(pid)
	if err != nil {
		return false, err
	}
	self, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("resolve own executable: %w", err)
	}
	return sameExeDarwin(comm, self), nil
}

// sameExeDarwin compares an observed `ps comm` value against our own executable
// path, tolerating macOS's truncation of the comm column.
func sameExeDarwin(observed, self string) bool {
	if sameExe(observed, self) {
		return true
	}
	// Truncation case: comm is a prefix of the real path. Require the basenames
	// to match too, so an unrelated process whose path happens to be a prefix of
	// ours is not misidentified as abox.
	if observed != "" && strings.HasPrefix(self, observed) {
		return filepath.Base(observed) == filepath.Base(self) ||
			strings.HasPrefix(filepath.Base(self), filepath.Base(observed))
	}
	return false
}
