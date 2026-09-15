package config

import (
	"runtime"
	"testing"
)

// skipOnWindows skips tests whose fixtures assert POSIX-shaped paths
// (e.g. /home/testuser, /run/user/1000, /var/lib/libvirt) or otherwise encode
// Linux/macOS filesystem semantics. abox's Windows support is real, but these
// assertions are inherently Unix-path-shaped: filepath.Join/Clean rewrite
// separators and filepath.IsAbs rejects rootless POSIX paths on Windows, so the
// hard-coded literals can never match there. The genuinely cross-platform
// behavior these areas cover (path-traversal rejection, extent validation) is
// exercised by tests that DO run on Windows (e.g. TestGetPaths_PathTraversal).
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("test fixtures assume POSIX path semantics; not applicable on Windows")
	}
}
