//go:build darwin

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRuntimeDirFallback_Darwin verifies the darwin seam returns a usable
// per-user runtime directory (macOS has neither XDG_RUNTIME_DIR nor
// /run/user/<uid>). Rather than restating the one-line implementation, it asserts
// the property downstream socket-path construction depends on: a non-empty,
// absolute directory.
func TestRuntimeDirFallback_Darwin(t *testing.T) {
	got := runtimeDirFallback()
	if got == "" {
		t.Fatal("runtimeDirFallback() returned an empty path")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("runtimeDirFallback() = %q, want an absolute path", got)
	}
}

// TestSecureRuntimeDir_DarwinUsesTempDir verifies that with XDG_RUNTIME_DIR
// unset (the macOS norm) SecureRuntimeDir selects $TMPDIR. macOS creates
// $TMPDIR as a per-user 0700 directory owned by the caller, so the security
// assertions pass. The expectation is the cleaned path: launchd exports TMPDIR
// with a trailing slash and os.TempDir() returns it verbatim, but the socket
// paths built from this directory must be clean (see SecureRuntimeDir).
func TestSecureRuntimeDir_DarwinUsesTempDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	got, err := SecureRuntimeDir()
	if err != nil {
		t.Fatalf("SecureRuntimeDir: %v", err)
	}
	if want := filepath.Clean(os.TempDir()); got != want {
		t.Fatalf("SecureRuntimeDir = %q, want %q", got, want)
	}
}
