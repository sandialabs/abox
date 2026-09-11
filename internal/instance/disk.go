package instance

import (
	"fmt"
	"os"

	"github.com/sandialabs/abox/internal/config"
)

// RemoveDiskDir deletes an instance's disk directory. Disk storage is
// user-owned, so this runs unprivileged.
//
// Invariant: paths.DiskDir = <validated storage>/instances/<name>, and
// config.validateStorageDir guarantees the storage dir is absolute and free of
// ".." traversal — so this RemoveAll cannot escape the instance's own storage
// tree.
func RemoveDiskDir(paths *config.Paths) error {
	if err := os.RemoveAll(paths.DiskDir); err != nil {
		return fmt.Errorf("remove disk directory %s: %w", paths.DiskDir, err)
	}
	return nil
}
