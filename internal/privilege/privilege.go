//go:build unix

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

// QEMU runtime user+group names by distribution: libvirt-qemu (Debian/Ubuntu),
// qemu (Fedora/Arch). Shared by the disk-group list and the storage helper's
// user/group resolution.
const (
	groupLibvirtQEMU = "libvirt-qemu"
	groupQEMU        = "qemu"
)

// qemuDiskGroups lists the groups used by QEMU to access disk images.
// The name varies by distribution: libvirt-qemu (Debian/Ubuntu), qemu (Fedora),
// or kvm.
var qemuDiskGroups = []string{groupLibvirtQEMU, groupQEMU, "kvm"}

// InLibvirtGroup checks if the current user is in the libvirt group.
func InLibvirtGroup() bool {
	return UserInGroup("libvirt")
}

// InLibvirtQemuGroup checks if the current user is in a QEMU disk access group.
// Returns true if the user is in any of the known QEMU disk access groups.
func InLibvirtQemuGroup() bool {
	return slices.ContainsFunc(qemuDiskGroups, UserInGroup)
}

// UserInGroup reports whether the current process is a member of the named OS
// group. It is the capability seam behind the abox-helper group check and the
// libvirt/QEMU disk-access checks: callers ask "is this user in group X" rather
// than reaching for a Linux-specific primitive. On platforms without POSIX
// groups the non-unix stub returns false (fail closed).
//
// Checks the real GID, effective GID, and supplementary groups. The real and
// effective GIDs are not guaranteed to appear in the supplementary group list
// (POSIX leaves it unspecified), so all three sources must be checked. This
// covers the newgrp case and primary-group membership.
func UserInGroup(groupName string) bool {
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

// libvirtImagesAboxDir is the shared parent for every user's abox disk storage.
// It MUST match config.LibvirtImagesDir; it is duplicated here (rather than
// imported) so this low-level privilege check keeps no dependency on config
// (mirroring storage_linux.go's libvirtImagesParent).
const libvirtImagesAboxDir = "/var/lib/libvirt/images/abox"

// CanAccessLibvirtImages checks whether the current user can use abox's libvirt
// disk storage. Storage now lives in a per-user subtree
// (/var/lib/libvirt/images/abox/<uid>) that the privilege helper provisions
// (owned by the caller, setgid to the QEMU group) on first use, so per-instance
// disk operations run unprivileged. The check therefore treats a present per-uid
// dir as good, and — because the helper provisions it lazily — treats "per-uid
// dir absent but the shared parent present" as good too (the next disk op will
// create it). Returns nil when access is possible, or an error with remediation.
func CanAccessLibvirtImages() error {
	perUser := filepath.Join(libvirtImagesAboxDir, strconv.Itoa(os.Getuid()))

	// Per-user root already provisioned: writable by the caller who owns it.
	if _, err := os.Stat(perUser); err == nil {
		if err := unix.Access(perUser, unix.W_OK); err != nil {
			return &errhint.ErrHint{
				Err:  fmt.Errorf("cannot write to your storage root %s", perUser),
				Hint: "it should be owned by you; if it is not, re-provision it (abox will do so on the next create) or remove it (may need sudo) and retry",
			}
		}
		return nil
	}

	// Not yet provisioned: OK as long as the shared parent exists — the helper
	// creates the per-user root lazily on the first disk operation. If the parent
	// is missing the helper creates it too (root-owned), so this is not fatal, but
	// surface it so `checkdeps`/`doctor` can note the helper will need to run.
	if _, err := os.Stat(libvirtImagesAboxDir); err == nil {
		return nil
	}
	return &errhint.ErrHint{
		Err:  fmt.Errorf("libvirt image storage %s does not exist yet", libvirtImagesAboxDir),
		Hint: "abox provisions your per-user storage root there (via the privilege helper) on the first `abox create`; ensure /var/lib/libvirt/images exists and the privilege helper is installed",
	}
}
