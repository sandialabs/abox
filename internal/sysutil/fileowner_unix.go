//go:build unix

// Package sysutil provides small OS-capability seams so the rest of abox can be
// written against a capability (file ownership, disk-free, restrictive umask)
// rather than a Linux-specific syscall. Each capability has a real Unix
// implementation and a fail-closed stub for platforms that lack the primitive.
package sysutil

import (
	"os"
	"syscall"
)

// FileOwner returns the owning uid and gid of fi. ok is false when the platform
// does not expose POSIX ownership through os.FileInfo (see the non-unix stub);
// callers that use ownership for a security decision MUST treat ok=false as
// "ownership unknown" and fail closed rather than assume the file is owned.
//
// syscall.Stat_t exists on every unix (linux, darwin, the BSDs) with Uid/Gid
// fields, so a single //go:build unix implementation covers them all.
func FileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
