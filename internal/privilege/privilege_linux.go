//go:build linux

package privilege

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/sandialabs/abox/internal/errhint"
)

// qemuDiskGroups lists the groups used by QEMU to access disk images.
// The name varies by distribution: libvirt-qemu (Debian/Ubuntu), qemu (Fedora),
// or kvm.
var qemuDiskGroups = []string{"libvirt-qemu", "qemu", "kvm"}

// InLibvirtGroup checks if the current user is in the libvirt group.
func InLibvirtGroup() bool {
	return InGroup("libvirt")
}

// InLibvirtQemuGroup checks if the current user is in a QEMU disk access group.
// Returns true if the user is in any of the known QEMU disk access groups.
func InLibvirtQemuGroup() bool {
	return slices.ContainsFunc(qemuDiskGroups, InGroup)
}

// CanAccessLibvirtImages checks if the current user/process can access libvirt disk paths.
// Returns nil if access is possible, or an error with remediation suggestions.
func CanAccessLibvirtImages() error {
	imagesDir := "/var/lib/libvirt/images"
	aboxDir := filepath.Join(imagesDir, "abox")

	// Check if we can write to the abox directory (or images dir if abox doesn't exist)
	checkDir := aboxDir
	if _, err := os.Stat(aboxDir); os.IsNotExist(err) {
		checkDir = imagesDir
	}

	// Check if directory exists
	if _, err := os.Stat(checkDir); os.IsNotExist(err) {
		return fmt.Errorf("directory %s does not exist", checkDir)
	}

	// Check write access
	if err := unix.Access(checkDir, unix.W_OK); err != nil {
		// Provide remediation suggestions
		// Detect which QEMU disk group exists on this system for the hint message.
		qemuGroup := qemuDiskGroups[0]
		for _, g := range qemuDiskGroups {
			if _, err := user.LookupGroup(g); err == nil {
				qemuGroup = g
				break
			}
		}
		suggestions := []string{
			"Add user to " + qemuGroup + " group: sudo usermod -aG " + qemuGroup + " " + os.Getenv("USER"),
			"Or set ACLs: sudo setfacl -m u:" + os.Getenv("USER") + ":rwx " + imagesDir,
		}
		return &errhint.ErrHint{
			Err:  fmt.Errorf("cannot write to %s", checkDir),
			Hint: fmt.Sprintf("Remediation options:\n  - %s\n  - %s", suggestions[0], suggestions[1]),
		}
	}

	return nil
}
