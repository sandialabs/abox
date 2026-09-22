//go:build unix

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSecureRuntimeDir_AcceptsOwned0700 verifies that a user-owned, 0700
// directory pointed to by XDG_RUNTIME_DIR is accepted on both linux and darwin.
func TestSecureRuntimeDir_AcceptsOwned0700(t *testing.T) {
	dir := t.TempDir() // owned by us
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)

	got, err := SecureRuntimeDir()
	if err != nil {
		t.Fatalf("SecureRuntimeDir: %v", err)
	}
	if got != dir {
		t.Fatalf("SecureRuntimeDir = %q, want %q", got, dir)
	}
}

// TestSecureRuntimeDir_RejectsWorldWritable verifies a world-writable directory
// (like a shared /tmp) is refused, since another user could hijack the socket.
func TestSecureRuntimeDir_RejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)

	if _, err := SecureRuntimeDir(); err == nil {
		t.Fatalf("expected SecureRuntimeDir to reject world-writable dir %q", dir)
	}
}

// TestSecureRuntimeDir_RejectsGroupWritable verifies a group-writable directory
// is also refused (only the owner may create the helper socket there).
func TestSecureRuntimeDir_RejectsGroupWritable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)

	if _, err := SecureRuntimeDir(); err == nil {
		t.Fatalf("expected SecureRuntimeDir to reject group-writable dir %q", dir)
	}
}

// TestSecureRuntimeDir_RejectsMissing verifies a non-existent directory is
// refused with a clear error rather than silently proceeding.
func TestSecureRuntimeDir_RejectsMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	t.Setenv("XDG_RUNTIME_DIR", dir)

	if _, err := SecureRuntimeDir(); err == nil {
		t.Fatalf("expected SecureRuntimeDir to reject missing dir %q", dir)
	}
}

// TestSecureRuntimeDir_CleansTrailingSlash verifies the returned directory is
// clean even when the source path carries a trailing separator. macOS launchd
// exports TMPDIR as "/var/folders/.../T/" and os.TempDir() returns it verbatim;
// callers append a filename to build the privilege-helper socket path, and the
// helper rejects a non-clean --socket argument, so a surviving trailing slash
// makes every helper spawn fail.
func TestSecureRuntimeDir_CleansTrailingSlash(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir+string(filepath.Separator))

	got, err := SecureRuntimeDir()
	if err != nil {
		t.Fatalf("SecureRuntimeDir: %v", err)
	}
	if got != dir {
		t.Fatalf("SecureRuntimeDir = %q, want %q", got, dir)
	}
	sock := filepath.Join(got, "abox-privilege-test.sock")
	if filepath.Clean(sock) != sock {
		t.Fatalf("socket path built from SecureRuntimeDir is not clean: %q", sock)
	}
}

// TestSecureRuntimeDir_RejectsNonDir verifies a file (not a directory) is
// refused.
func TestSecureRuntimeDir_RejectsNonDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", f)

	if _, err := SecureRuntimeDir(); err == nil {
		t.Fatalf("expected SecureRuntimeDir to reject non-directory %q", f)
	}
}
