// Package privilege provides helpers for checking user privileges.
package privilege

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/sandialabs/abox/internal/errhint"
)

// InLibvirtGroup checks if the current user is in the libvirt group.
func InLibvirtGroup() bool {
	return InGroup("libvirt")
}

// InLibvirtQemuGroup checks if the current user is in the libvirt-qemu or kvm group.
// These groups are used by QEMU processes to access disk images.
func InLibvirtQemuGroup() bool {
	return InGroup("libvirt-qemu") || InGroup("kvm")
}

// InGroup checks if the current process is in the specified group.
// Checks the real GID, effective GID, and supplementary groups. The real and
// effective GIDs are not guaranteed to appear in the supplementary group list
// (POSIX leaves it unspecified), so all three sources must be checked. This
// covers the newgrp case and primary-group membership.
func InGroup(groupName string) bool {
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return false
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return false
	}

	// Check real and effective GID first.
	if os.Getgid() == gid || os.Getegid() == gid {
		return true
	}

	groups, err := os.Getgroups()
	if err != nil {
		return false
	}

	return slices.Contains(groups, gid)
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
		suggestions := []string{
			"Add user to libvirt-qemu group: sudo usermod -aG libvirt-qemu " + os.Getenv("USER"),
			"Or set ACLs: sudo setfacl -m u:" + os.Getenv("USER") + ":rwx " + imagesDir,
		}
		return &errhint.ErrHint{
			Err:  fmt.Errorf("cannot write to %s", checkDir),
			Hint: fmt.Sprintf("Remediation options:\n  - %s\n  - %s", suggestions[0], suggestions[1]),
		}
	}

	return nil
}
