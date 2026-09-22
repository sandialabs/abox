//go:build !unix

package privilege

import "testing"

// TestUserInGroupFailsClosed verifies group membership always reports false on
// platforms without POSIX groups, so no membership check can accidentally grant
// access to the setuid helper or assume libvirt disk-store reachability.
func TestUserInGroupFailsClosed(t *testing.T) {
	if UserInGroup("wheel") {
		t.Fatal("expected UserInGroup to report false on a non-unix platform")
	}
	if InLibvirtGroup() {
		t.Fatal("expected InLibvirtGroup to report false on a non-unix platform")
	}
	if InLibvirtQemuGroup() {
		t.Fatal("expected InLibvirtQemuGroup to report false on a non-unix platform")
	}
}

// TestCanAccessLibvirtImagesUnsupported verifies the libvirt disk store is
// reported unreachable (an error) on non-unix platforms.
func TestCanAccessLibvirtImagesUnsupported(t *testing.T) {
	if err := CanAccessLibvirtImages(); err == nil {
		t.Fatal("expected CanAccessLibvirtImages to return an error on a non-unix platform")
	}
}
