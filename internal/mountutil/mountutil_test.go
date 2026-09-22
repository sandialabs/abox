//go:build unix

package mountutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsMounted(t *testing.T) {
	// A freshly created subdirectory lives on the same filesystem as its parent,
	// so it is not a mount point.
	dir := t.TempDir()
	sub := filepath.Join(dir, "child")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if IsMounted(sub) {
		t.Errorf("IsMounted(%q) = true; want false for a plain subdirectory", sub)
	}

	// A path that does not exist is treated as not mounted.
	if IsMounted(filepath.Join(dir, "does-not-exist")) {
		t.Error("IsMounted(nonexistent) = true; want false")
	}
}
