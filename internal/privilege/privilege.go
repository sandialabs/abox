// Package privilege provides helpers for checking user privileges.
package privilege

import (
	"os"
	"os/user"
	"slices"
	"strconv"
)

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
