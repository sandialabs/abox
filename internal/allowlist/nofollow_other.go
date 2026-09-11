//go:build !unix

package allowlist

import (
	"fmt"
	"os"
)

// OpenFileNoFollow opens a file, refusing to follow a symlink at the final path
// component. Windows has no atomic O_NOFOLLOW equivalent, so this uses an
// Lstat check before opening. That reintroduces a small TOCTOU window the Unix
// implementation avoids, but it still rejects the common symlink-swap case.
func OpenFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("path is a symlink (security risk): %s", path)
	}
	return os.OpenFile(path, flag, perm)
}
