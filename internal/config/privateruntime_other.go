//go:build !unix

package config

import "os"

// privateRuntimeFallback on non-unix platforms (Windows) returns the system
// temp directory as-is: %TEMP% is already per-user there, so the shared-tmp
// collision the unix fallback defends against does not exist, and the unix
// verification is meaningless (Go reports a fixed 0777 mode for Windows
// directories and uids are not applicable).
func privateRuntimeFallback() (string, error) {
	return os.TempDir(), nil
}
