//go:build linux

package daemon

import (
	"fmt"
	"os"
)

// isAboxProcess verifies a PID belongs to our executable by reading the
// /proc/<pid>/exe symlink. This is more secure than checking cmdline, which
// could match any process that happens to have "abox" in its arguments
// (e.g. "cat /home/abox/file").
//
// Contract (see IsAboxProcess):
//   - readlink error → unverifiable (false, err); the process may be ours but
//     gone, or owned by another user we can't introspect. Callers must not act
//     on this as a confirmed mismatch.
//   - readlink ok but path differs → confirmed not-abox (false, nil).
//
// The "(deleted)" suffix the kernel appends after the binary is replaced on
// disk is tolerated by comparing the path with that suffix stripped, so an
// upgraded-in-place abox still recognizes its own daemons.
func isAboxProcess(pid int) (bool, error) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false, fmt.Errorf("read /proc/%d/exe: %w", pid, err)
	}
	currentExe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("resolve own executable: %w", err)
	}
	return sameExe(exePath, currentExe), nil
}
