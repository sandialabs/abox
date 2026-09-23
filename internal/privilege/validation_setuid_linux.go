//go:build linux

package privilege

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ValidateSetuidSocketPath is the strict --socket validator used ONLY by the
// setuid abox-helper binary. Unlike the shared ValidateSocketPath (which the
// root/sudo cobra path also uses and which only checks absolute+clean), this
// enforces that the socket lives in a directory the caller genuinely controls, so
// the root-privileged chown/chmod/unlink the helper performs on the path cannot be
// redirected via a parent-directory or symlink swap.
//
// It does NOT hardcode /run/user/<ruid>: SecureRuntimeDir (used by the client that
// generated the path) honors $XDG_RUNTIME_DIR first, so a legitimate socket may
// live elsewhere. The setuid binary has os.Clearenv()'d and cannot read
// $XDG_RUNTIME_DIR, so instead of matching a literal path we gate on the security
// PROPERTIES of the parent directory:
//
//   - it is a real directory (Lstat, not following a symlink),
//   - owned by the caller (ruid) or root — a root-owned parent (e.g.
//     /run/user/<ruid>, created by pam_systemd) defeats a non-root swap,
//   - not group- or other-writable,
//
// and the target itself is either absent or already an ruid-owned socket (never a
// symlink, regular file, or device planted at the path).
func ValidateSetuidSocketPath(socketPath string, ruid int) error {
	// Reuse the base absolute+clean checks first.
	if err := ValidateSocketPath(socketPath); err != nil {
		return err
	}

	dir := parentDir(socketPath)

	// Lstat the parent (no symlink following) and verify its properties.
	var dst unix.Stat_t
	if err := unix.Lstat(dir, &dst); err != nil {
		return fmt.Errorf("cannot stat socket parent directory %s: %w", dir, err)
	}
	if dst.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("socket parent %s is not a directory (or is a symlink)", dir)
	}
	if int(dst.Uid) != ruid && dst.Uid != 0 {
		return fmt.Errorf("socket parent %s is not owned by the caller (uid %d) or root (owner uid %d)", dir, ruid, dst.Uid)
	}
	if dst.Mode&0o022 != 0 {
		return fmt.Errorf("socket parent %s is group/other-writable (mode %o); refusing to use it", dir, dst.Mode&0o777)
	}

	// The target must be absent, or an existing socket owned by the caller. A
	// symlink/regular file/device planted here would otherwise be chowned/chmod'd
	// or unlinked as root.
	var st unix.Stat_t
	if err := unix.Lstat(socketPath, &st); err != nil {
		if os.IsNotExist(err) {
			return nil // absent is fine; the helper's bind will create it
		}
		return fmt.Errorf("cannot stat socket path %s: %w", socketPath, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("socket path %s exists and is not a socket (mode %o); refusing to operate on it", socketPath, st.Mode&unix.S_IFMT)
	}
	if int(st.Uid) != ruid {
		return fmt.Errorf("socket path %s is not owned by the caller (uid %d, owner uid %d)", socketPath, ruid, st.Uid)
	}
	return nil
}

// parentDir returns the directory component of a cleaned absolute path.
func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}
