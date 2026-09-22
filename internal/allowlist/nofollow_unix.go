//go:build unix

package allowlist

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// OpenFileNoFollow opens a file with O_NOFOLLOW to prevent symlink attacks.
// This provides atomic TOCTOU protection - the check and open happen in one syscall.
func OpenFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flag|unix.O_NOFOLLOW, uint32(perm))
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("path is a symlink (security risk): %s", path)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
