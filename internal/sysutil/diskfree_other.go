//go:build !unix

package sysutil

import "errors"

// ErrDiskFreeUnsupported is returned by DiskFreeBytes on platforms without a
// statfs-style API wired up (currently Windows). Callers (e.g. doctor's
// host-disk check) must degrade gracefully — report the check as skipped rather
// than crash — instead of treating a zero return as "no space".
var ErrDiskFreeUnsupported = errors.New("querying free disk space is not supported on this platform")

// DiskFreeBytes is unsupported off unix. It returns ErrDiskFreeUnsupported and a
// zero count; it never reports a fake amount of free space.
func DiskFreeBytes(_ string) (uint64, error) {
	return 0, ErrDiskFreeUnsupported
}
