//go:build darwin

package sysutil

import "golang.org/x/sys/unix"

// DiskFreeBytes returns the number of bytes available to an unprivileged user on
// the filesystem backing path. See diskfree_linux.go for the shared rationale;
// on darwin Bsize is uint32, so its widening to uint64 is safe and needs no
// gosec directive.
func DiskFreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
