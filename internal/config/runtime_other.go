//go:build !linux && !darwin

package config

import "os"

// runtimeDirFallback returns the default per-user runtime directory on platforms
// without a well-known one. There is no /run/user/<uid> (Linux) or launchd
// $TMPDIR (macOS) equivalent to rely on, so os.TempDir() is the most portable
// per-user-writable location. The privilege helper is not supported off
// Linux/darwin anyway, so this fallback exists only to let the tree cross-compile
// (and to keep XDG_RUNTIME_DIR resolution total).
func runtimeDirFallback() string {
	return os.TempDir()
}
