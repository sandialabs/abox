//go:build linux

package privilege

import (
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"
)

// SocketGroupAccess describes the owning group of a unix socket and whether the
// current process can reach it by group membership.
type SocketGroupAccess struct {
	Group    string // owning group name, or the numeric GID if it can't be resolved
	GID      int
	IsMember bool // whether the current process is a member of the owning group
}

// inGID reports whether the current process belongs to gid (real, effective, or
// supplementary).
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

// CheckSocketGroupAccess stats the socket at path and reports its owning group
// and whether the caller is a member. Used to warn when the libvirt-created
// virtio-serial monitor socket is owned by a qemu group the user is not in (the
// monitor daemon would then silently capture zero events). Linux-only: the
// socket-group model is specific to libvirt/qemu on Linux.
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
