// Package privilege provides helpers for checking user privileges.
package privilege

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

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

	return inGID(gid)
}

// inGID reports whether the current process belongs to the given GID, checking
// the real GID, effective GID, and supplementary groups (POSIX leaves it
// unspecified whether the real/effective GIDs appear in the supplementary list).
func inGID(gid int) bool {
	if os.Getgid() == gid || os.Getegid() == gid {
		return true
	}

	groups, err := os.Getgroups()
	if err != nil {
		return false
	}

	return slices.Contains(groups, gid)
}

// SocketGroupAccess describes a unix socket's owning group and whether the
// current process can reach it via that group's permissions.
type SocketGroupAccess struct {
	Group    string // owning group name, or the numeric GID if it can't be resolved
	GID      int
	IsMember bool // whether the current process is a member of the owning group
}

// CheckSocketGroupAccess stats the socket at path and reports its owning group
// and whether the current process is a member of it. This is the authoritative
// check for whether a connect() will be permitted via group permissions — the
// common case for libvirt-created chardev sockets, which are group-owned (e.g.
// kvm/libvirt-qemu) rather than owned by the invoking user.
func CheckSocketGroupAccess(path string) (SocketGroupAccess, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SocketGroupAccess{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return SocketGroupAccess{}, fmt.Errorf("cannot determine ownership of %s", path)
	}

	gid := int(stat.Gid)
	gidStr := strconv.Itoa(gid)
	access := SocketGroupAccess{GID: gid, Group: gidStr, IsMember: inGID(gid)}
	if g, err := user.LookupGroupId(gidStr); err == nil {
		access.Group = g.Name
	}
	return access, nil
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
