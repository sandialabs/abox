package instance

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
)

// RequireMigrated returns an actionable error when an instance still uses the
// legacy root-owned disk location. Disk-touching commands (start, up, export,
// remove, and `down --remove`) gate on this: those operations now run
// unprivileged and cannot manage root-owned images, so the user must run
// `abox migrate` first. Read-only and teardown-without-disk commands (status,
// list, stop, plain `down`, doctor) do NOT gate, so a legacy instance remains
// inspectable and stoppable.
func RequireMigrated(inst *config.Instance, paths *config.Paths) error {
	if !config.IsLegacyStorage(inst, paths) {
		return nil
	}
	return &errhint.ErrHint{
		Err:  fmt.Errorf("instance %q uses the legacy root-owned disk location %s", inst.Name, config.LibvirtImagesDir),
		Hint: "run `abox migrate " + inst.Name + "` to move it under " + config.LibvirtStorageDir() + " (one-time, needs sudo)",
	}
}
