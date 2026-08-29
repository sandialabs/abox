//go:build darwin

package remove

import (
	"fmt"
	"os/exec"
	"strings"
)

// doUnmount unmounts a macFUSE/SSHFS mount on macOS. The normal path uses
// `umount`; with force it uses `diskutil unmount force`, which reliably detaches
// a busy macFUSE volume. macOS has no lazy-unmount equivalent to Linux's
// `fusermount -z`, so force maps to a hard unmount here.
func doUnmount(path string, force bool) error {
	var cmd *exec.Cmd
	if force {
		cmd = exec.Command("diskutil", "unmount", "force", path)
	} else {
		cmd = exec.Command("umount", path)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unmount: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
