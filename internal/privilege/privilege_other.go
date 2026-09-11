//go:build !unix

// Package privilege provides helpers for checking user privileges.
package privilege

import "errors"

// The privilege helper and libvirt disk store are Linux/Unix concepts. On
// platforms without POSIX groups (Windows) every membership check fails closed
// (returns false) and the libvirt-images access check reports the capability as
// unsupported. This is the safe direction: a false membership never grants
// access to the setuid helper or assumes disk-store reachability.

// UserInGroup always reports false on non-unix platforms (no POSIX groups).
func UserInGroup(_ string) bool { return false }

// InLibvirtGroup always reports false on non-unix platforms.
func InLibvirtGroup() bool { return false }

// InLibvirtQemuGroup always reports false on non-unix platforms.
func InLibvirtQemuGroup() bool { return false }

// CanAccessLibvirtImages reports the libvirt disk store as unreachable on
// non-unix platforms, since there is no libvirt/QEMU there.
func CanAccessLibvirtImages() error {
	return errors.New("libvirt image store access is not supported on this platform")
}
