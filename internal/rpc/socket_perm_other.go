//go:build !linux

package rpc

import (
	"fmt"
	"net"
	"os"
)

// applySocketPermissions is the non-Linux (darwin) form: path-based chmod/chown.
// The fd-based variant (socket_perm_linux.go) is Linux-only because the
// fchmod/fchown-on-AF_UNIX-fd behavior differs across kernels and has not been
// validated on darwin; the darwin helper is launched via sudo (no setuid path)
// and the socket lives in a per-user 0700 $TMPDIR, so the path-based form is
// acceptable here.
func applySocketPermissions(_ net.Listener, path string, mode os.FileMode, allowedUID int) error {
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to chmod socket: %w", err)
	}
	if err := os.Chown(path, allowedUID, -1); err != nil {
		return fmt.Errorf("failed to chown socket: %w", err)
	}
	return nil
}
