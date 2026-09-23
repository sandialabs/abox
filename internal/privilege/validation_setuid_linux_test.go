//go:build linux

package privilege

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestValidateSetuidSocketPath_AcceptsOwnedSecureDir accepts a socket path whose
// parent is a caller-owned, non-world-writable directory with no target present.
func TestValidateSetuidSocketPath_AcceptsOwnedSecureDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // ensure not group/other-writable
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "helper.sock")
	if err := ValidateSetuidSocketPath(sock, os.Getuid()); err != nil {
		t.Fatalf("expected acceptance of owned secure dir, got %v", err)
	}
}

// TestValidateSetuidSocketPath_RejectsWorldWritableParent rejects a socket whose
// parent directory is group/other-writable.
func TestValidateSetuidSocketPath_RejectsWorldWritableParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "helper.sock")
	if err := ValidateSetuidSocketPath(sock, os.Getuid()); err == nil {
		t.Fatal("expected rejection of world-writable parent directory")
	}
}

// TestValidateSetuidSocketPath_RejectsSymlinkAtTarget rejects a symlink planted
// at the socket path (which a path-based chown/unlink would follow).
func TestValidateSetuidSocketPath_RejectsSymlinkAtTarget(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "helper.sock")
	if err := os.Symlink("/etc/shadow", sock); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSetuidSocketPath(sock, os.Getuid()); err == nil {
		t.Fatal("expected rejection of a symlink planted at the socket path")
	}
}

// TestValidateSetuidSocketPath_RejectsRegularFileAtTarget rejects a regular file
// at the socket path (not a socket).
func TestValidateSetuidSocketPath_RejectsRegularFileAtTarget(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "helper.sock")
	if err := os.WriteFile(sock, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSetuidSocketPath(sock, os.Getuid()); err == nil {
		t.Fatal("expected rejection of a regular file at the socket path")
	}
}

// TestValidateSetuidSocketPath_AcceptsOwnedSocketAtTarget accepts a pre-existing
// socket owned by the caller (the stale-socket reclaim case).
func TestValidateSetuidSocketPath_AcceptsOwnedSocketAtTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "helper.sock")
	ln, err := (&onlyListen{}).listen(sock)
	if err != nil {
		t.Skipf("cannot create unix socket in this environment: %v", err)
	}
	defer ln()
	if err := ValidateSetuidSocketPath(sock, os.Getuid()); err != nil {
		t.Fatalf("expected acceptance of caller-owned socket, got %v", err)
	}
}

// TestValidateSetuidSocketPath_RejectsRelativePath rejects a non-absolute path
// (delegated to the base ValidateSocketPath).
func TestValidateSetuidSocketPath_RejectsRelativePath(t *testing.T) {
	if err := ValidateSetuidSocketPath("relative/helper.sock", os.Getuid()); err == nil {
		t.Fatal("expected rejection of a relative socket path")
	}
}

// onlyListen creates a bound AF_UNIX socket at a path and returns a cleanup func.
type onlyListen struct{}

func (onlyListen) listen(path string) (func(), error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return func() { _ = unix.Close(fd); _ = os.Remove(path) }, nil
}
