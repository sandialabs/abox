//go:build linux

package privilege

import (
	"golang.org/x/sys/unix"
)

// removeSocket unlinks the helper socket via a directory-fd-relative unlinkat so
// the root-privileged cleanup cannot be redirected by a parent-directory or
// symlink swap. The parent directory is opened with O_DIRECTORY|O_NOFOLLOW,
// pinning its inode; unlinkat then resolves only the final path component within
// that pinned directory (unlink never follows a terminal symlink, so a socket
// replaced by a symlink is removed as the link, not its target).
func removeSocket(socketPath string) error {
	dir := parentDir(socketPath)
	base := socketPath[len(dir):]
	for len(base) > 0 && base[0] == '/' {
		base = base[1:]
	}

	dirFD, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dirFD) }()

	return unix.Unlinkat(dirFD, base, 0)
}
