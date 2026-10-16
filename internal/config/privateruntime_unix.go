//go:build unix

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// privateRuntimeFallback returns the per-uid 0700 fallback directory for runtime
// sockets/PID files under the SHARED system temp directory, creating and then
// verifying it. On error the attempted directory is still returned so callers
// can keep computing (unusable) paths — see privateRuntimeDirLenient.
func privateRuntimeFallback() (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("abox-%d", os.Getuid()))
	// Deliberately the real filesystem, not the fsys seam: the squat guard below
	// (Lstat, ownership, mode) only means anything against the real shared /tmp,
	// and MkdirAll must create what Lstat then inspects.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return dir, fmt.Errorf("create private runtime directory %s: %w", dir, err)
	}
	if err := assertPrivateFallbackDir(dir); err != nil {
		return dir, err
	}
	return dir, nil
}

// assertPrivateFallbackDir verifies the per-uid temp fallback is safe to host
// sockets: an actual directory (not a symlink another user planted at the
// predictable name), owned by the caller, with no group/other permission bits.
// Lstat is deliberate — MkdirAll follows a pre-existing symlink and happily
// "succeeds" into the attacker's target directory. Uses the real filesystem
// (not the fsys seam): this guards a real-world /tmp property, and the fsys
// mock has no Lstat. The error remediation leads with XDG_RUNTIME_DIR because a
// squatted entry under a sticky-bit /tmp can only be removed by its owner or
// root. Shares the ownership/permission core with assertSecureRuntimeDir via
// assertOwnedPrivateDir; the stat discipline (Lstat here vs the fsys seam
// there) is deliberately different and must stay with each caller.
func assertPrivateFallbackDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("verify private runtime directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private runtime directory %s is a symlink (another user may have planted it); set XDG_RUNTIME_DIR, or remove the entry (needs root under a sticky /tmp)", dir)
	}
	return assertOwnedPrivateDir(info, 0o077,
		fmt.Sprintf("private runtime directory %s", dir),
		"set XDG_RUNTIME_DIR, or remove the entry (needs root under a sticky /tmp)")
}
