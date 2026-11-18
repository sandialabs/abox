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

// TestPrivateRuntimeDir_NonUnixFallback pins the Windows behavior: the fallback
// is the per-user %TEMP% as-is — no unix verification (Go reports a fixed 0777
// mode for Windows directories and uids are not applicable), so PrivateRuntimeDir
// (and therefore GetPaths) must never hard-fail there. CI runs this package on
// windows-latest; this test is the explicit gate, TestGetPaths_PathTraversal the
// implicit one.
func TestPrivateRuntimeDir_NonUnixFallback(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("pins the !unix fallback; meaningful only on Windows")
	}
	dir, err := PrivateRuntimeDir()
	if err != nil {
		t.Fatalf("PrivateRuntimeDir on Windows: %v", err)
	}
	if dir == "" {
		t.Fatal("PrivateRuntimeDir on Windows returned an empty directory")
	}
}
