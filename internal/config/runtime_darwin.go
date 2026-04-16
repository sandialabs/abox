//go:build darwin

package config

import "os"

// runtimeDirFallback returns the default runtime directory on macOS.
// os.TempDir() returns the per-user $TMPDIR (e.g. /var/folders/xx/.../T/)
// which is private to the current user.
func runtimeDirFallback() string {
	return os.TempDir()
}
