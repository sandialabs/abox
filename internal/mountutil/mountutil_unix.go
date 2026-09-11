//go:build unix

// Package mountutil provides small cross-platform helpers for working with
// filesystem mounts on the host.
package mountutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// IsMounted reports whether path is a mount point on a DISTINCT device from its
// parent. It compares the device ID (st_dev) of path against its parent
// directory: the two differ across a mount boundary, including for FUSE/SSHFS
// mounts. This avoids shelling out to the Linux-only `mountpoint` binary, so it
// works identically on Linux and macOS.
//
// Limitation: a same-device mount (e.g. a bind mount) shares its parent's st_dev
// and is therefore reported as NOT mounted. This is safe for abox's only mount
// type — SSHFS/FUSE, which always lands on a distinct device — but callers must
// not rely on IsMounted to detect bind mounts.
//
// A path that does not exist, or whose parent cannot be stat'd, is treated as
// not mounted. The one exception is ENOTCONN ("transport endpoint is not
// connected"): a FUSE/SSHFS mount whose server has died still exists in the
// kernel mount table (only its backing connection is gone) and stat'ing the
// mount point returns ENOTCONN. Report such a stale mount as MOUNTED — it is
// exactly the dangling mount `abox unmount --force` exists to clean up, and
// treating it as absent would leave it undetectable and unremovable.
func IsMounted(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return errors.Is(err, syscall.ENOTCONN)
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	pst, ok2 := parent.Sys().(*syscall.Stat_t)
	if !ok || !ok2 {
		return false
	}
	// Dev has the same type on both sides (uint64 on Linux, int32 on darwin), so
	// they compare directly without a width-normalizing conversion.
	return st.Dev != pst.Dev
}
