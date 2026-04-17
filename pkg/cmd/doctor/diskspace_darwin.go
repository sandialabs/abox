//go:build darwin

package doctor

import "syscall"

// statfsAvailableBytes returns the number of bytes available to a non-privileged
// user at path. On darwin, Statfs_t.Bsize is uint32.
func statfsAvailableBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
