//go:build darwin

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/childproc"
)

// procComm returns the executable path of a PID via `ps -p <pid> -o comm=`.
// macOS has no /proc/<pid>/exe, and CGO is disabled (CGO_ENABLED=0) so the
// libproc proc_pidpath() syscall is unavailable; ps is the portable way to
// resolve a PID to its executable path. On macOS the `comm` column is the full
// executable path (e.g. /Users/me/.local/bin/abox), not just the basename.
//
// It is a package variable so tests can substitute a deterministic
// implementation without shelling out.
var procComm = psComm

func psComm(pid int) (string, error) {
	// Delegate the actual `ps -p <pid> -o comm=` shell-out to childproc.LookupComm
	// so there is a single macOS PID->comm implementation; add the daemon-specific
	// empty-string-to-error wrapping (an empty comm is "unverifiable", not "not
	// abox").
	comm, err := childproc.LookupComm(pid)
	if err != nil {
		// ps exits non-zero when the PID does not exist; surface as an error so
		// the caller can distinguish "gone/unverifiable" from "not abox".
		return "", fmt.Errorf("ps -p %d: %w", pid, err)
	}
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
// fail-safe (never signal a process we cannot positively rule out), comparison
// is tolerant: an exact path match, OR the observed value being a non-empty
// prefix of our executable path AND sharing a compatible basename, both count
// as "ours". Anything else is a confirmed mismatch.
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
	// Truncation case: macOS may truncate the `comm` column for very long paths,
	// so a legitimately-ours daemon can report a proper prefix of our real
	// executable path. Accept only when the observed value is a prefix of `self`
	// whose truncated-off tail stays within self's FINAL path component (no
	// intervening separator); a prefix that stops at a directory boundary belongs
	// to a different binary and is rejected.
	//
	// Residual limitation: two sibling binaries whose basenames are prefixes of
	// one another (e.g. "abox" vs "aboxxl") are inherently indistinguishable once
	// comm is truncated, so this can still over-match in that narrow case. abox
	// ships a single "abox" binary, so it is not reachable in practice, and the
	// guard only ever gates SIGTERM to a pid we wrote to our own pidfile.
	if observed != "" && observed != self && strings.HasPrefix(self, observed) {
		return !strings.Contains(self[len(observed):], string(filepath.Separator))
	}
	return false
}
