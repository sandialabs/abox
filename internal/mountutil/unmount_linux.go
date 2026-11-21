//go:build linux

package mountutil

import (
	"fmt"
	"os/exec"
	"strings"
)

// Unmount unmounts a FUSE/SSHFS mount on Linux via fusermount. With force it
// performs a lazy unmount (-z), which detaches a busy mount immediately.
func Unmount(path string, force bool) error {
	args := []string{"-u"}
	if force {
		args = append(args, "-z") // lazy unmount
	}
	args = append(args, path)

	cmd := exec.Command("fusermount", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unmount: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
