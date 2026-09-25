//go:build !linux

package privilege

import "os"

// removeSocket is the non-Linux (darwin) fallback: a path-based remove. The
// darwin helper runs via sudo (no setuid path) and the socket lives in a per-user
// 0700 $TMPDIR, so the directory-fd-relative unlink hardening (see
// socket_remove_linux.go) is not required here.
func removeSocket(socketPath string) error {
	return os.Remove(socketPath)
}
