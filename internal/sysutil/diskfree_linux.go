//go:build linux

package sysutil

import "golang.org/x/sys/unix"

// DiskFreeBytes returns the number of bytes available to an unprivileged user on
// the filesystem backing path. It uses statfs via golang.org/x/sys/unix, whose
// Statfs_t exposes Bavail (blocks available) and Bsize (block size).
//
// The field integer widths differ per OS (see diskfree_darwin.go), so the
// conversions live in per-OS files rather than a shared //go:build unix file.
func DiskFreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	// Bavail is uint64 on linux (no conversion); Bsize is int64, but a block size
	// is never negative.
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // Bsize is int64 on linux; block size is never negative
}
