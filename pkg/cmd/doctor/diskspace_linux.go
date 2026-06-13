//go:build linux

package doctor

import "syscall"

// statfsAvailableBytes returns the number of bytes available to a non-privileged
// user at path. On Linux, Statfs_t.Bsize is int64 and always positive in practice,
// so the conversion to uint64 is safe.
func statfsAvailableBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil //nolint:gosec // G115: Bsize is int64 but always a positive block size
}
