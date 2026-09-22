//go:build darwin

package config

import "os"

// runtimeDirFallback returns the default per-user runtime directory on macOS.
// macOS has neither XDG_RUNTIME_DIR nor /run/user/<uid>; the correct per-user
// private location is $TMPDIR (e.g. /var/folders/xx/.../T/), which launchd
// creates with mode 0700 owned by the current user. os.TempDir() returns that
// value.
func runtimeDirFallback() string {
	return os.TempDir()
}
