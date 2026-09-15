// Package backendtest provides shared test helpers for the backend packages.
package backendtest

import (
	"os"
	"runtime"
	"testing"
)

// ShortDataHome returns a short-path temp directory suitable for use as
// XDG_DATA_HOME in backend tests, registering cleanup on t.
//
// t.TempDir() on macOS returns a long /var/folders/... path. Once the instance
// socket paths are appended (.../abox/instances/<name>/monitor.sock, run/vmnet.sock),
// the absolute path overflows the 103-byte sun_path limit that
// config.ValidateSocketPaths enforces on Darwin (see config/socketpath_darwin.go),
// making EnsureDirs fail before a socket is ever bound. Rooting the base under
// /tmp keeps it short enough for the sockets to fit. On Windows the sun_path
// limit is not enforced (socketpath_other.go), so the default temp root is fine.
func ShortDataHome(t *testing.T) string {
	t.Helper()
	root := "/tmp"
	if runtime.GOOS == "windows" {
		root = "" // os.MkdirTemp uses os.TempDir(); sun_path limit is a no-op here
	}
	// Intentionally not t.TempDir(): on macOS its /var/folders root is too long
	// for the sun_path limit (see doc comment above).
	dir, err := os.MkdirTemp(root, "abox") //nolint:usetesting // need a short root, see above
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
