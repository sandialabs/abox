//go:build linux

package rpc

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// applySocketPermissions sets the mode and owner of a just-bound unix socket by
// operating on an fd that is pinned to the socket's exact inode, immune to a
// path swap racing the operation.
//
// Threat: the abox-helper runs as root and a caller who controls the --socket
// path can, in the window after net.Listen binds the socket, unlink it and plant
// a symlink at the same name. Path-based os.Chmod would follow that symlink and
// chmod an attacker-named root file. So would fchmodat: Linux's fchmodat does not
// implement AT_SYMLINK_NOFOLLOW (it returns EOPNOTSUPP), so it always follows a
// terminal symlink — meaning the chmod fires against the wrong target before any
// later symlink-safe check could catch it.
//
// Defence, in order:
//  1. Open the parent dir O_DIRECTORY|O_NOFOLLOW (pins the directory inode; a dir
//     swapped to a symlink is rejected here).
//  2. Openat the final component O_PATH|O_NOFOLLOW (does NOT follow a terminal
//     symlink — it opens a handle to the link itself, which we then reject).
//  3. Fstat the handle and require it is a socket (S_IFSOCK). A planted symlink,
//     regular file, or directory is refused before any mode change.
//  4. chmod/chown via /proc/self/fd/<fd>, which resolves to the exact inode
//     captured at open time — so even a subsequent path swap cannot redirect it.
//
// Also note: fchmod/fchown directly on the socket fd is NOT usable — empirically
// fchmod on a bound AF_UNIX socket fd is a silent no-op on the on-disk mode the
// kernel checks at connect() time. Hence the /proc/self/fd path form.
//
// (ValidateSetuidSocketPath additionally confines the path up front; this is the
// operation-time re-check that actually closes the race.)
func applySocketPermissions(_ net.Listener, path string, mode os.FileMode, allowedUID int) error {
	dir, base := splitDir(path)

	dirFD, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open socket parent dir: %w", err)
	}
	defer func() { _ = unix.Close(dirFD) }()

	// Open the final component WITHOUT following a terminal symlink, pinning the
	// inode for the chmod/chown below.
	fd, err := unix.Openat(dirFD, base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open socket path: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	// Require the pinned inode to be a socket — reject a symlink/regular/dir that
	// an attacker may have swapped in after bind.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat socket path: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("socket path is not a socket (type %o); refusing to chmod/chown it", st.Mode&unix.S_IFMT)
	}

	// Operate on the pinned inode via /proc/self/fd, which cannot be redirected by
	// a subsequent path swap. (chmod/chown through an O_PATH fd's magic-symlink is
	// the supported way to mutate an fd-pinned inode when fchmod/fchown on the fd
	// itself is unavailable — as it is for O_PATH and for socket fds.)
	proc := "/proc/self/fd/" + strconv.Itoa(fd)
	if err := unix.Chmod(proc, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	if err := unix.Chown(proc, allowedUID, -1); err != nil {
		return fmt.Errorf("chown socket: %w", err)
	}

	// Verify the change actually took effect (fchmod-on-socket-fd was a silent
	// no-op historically; also guards against an unexpected mapping) — fail closed.
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat socket after chmod/chown: %w", err)
	}
	if os.FileMode(st.Mode).Perm() != mode.Perm() {
		return fmt.Errorf("socket mode did not take effect: got %o, want %o", os.FileMode(st.Mode).Perm(), mode.Perm())
	}
	if int(st.Uid) != allowedUID {
		return fmt.Errorf("socket owner did not take effect: got uid %d, want %d", st.Uid, allowedUID)
	}
	return nil
}

// splitDir splits an absolute path into its directory and final component.
func splitDir(p string) (dir, base string) {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			d := p[:i]
			if d == "" {
				d = "/"
			}
			return d, p[i+1:]
		}
	}
	return ".", p
}
