//go:build unix

package sysutil

import "syscall"

// WithUmask runs fn with the process umask set to mask, restoring the previous
// umask afterward. Use this when a caller's mkdir/open mode must land exactly as
// requested, independent of the ambient umask — e.g. a mode that must include a
// specific permission bit (like setgid's accompanying group r-x) that an
// unusually restrictive ambient umask (0o077, or any umask masking group bits)
// would otherwise silently strip, with no way to safely fix it up afterward (an
// unprivileged, non-group-member chmod would clear setgid — see
// internal/backend/libvirt/disk.go's prepareDir).
//
// The umask is process-global, so callers should keep fn short and must not rely
// on concurrent goroutines observing a particular umask while fn runs.
func WithUmask(mask int, fn func()) {
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	fn()
}

// WithRestrictiveUmask runs fn with the process umask set to 0o077, restoring
// the previous umask afterward. This ensures files/sockets created inside fn are
// owner-only, closing the race window between creation and an explicit chmod.
func WithRestrictiveUmask(fn func()) {
	WithUmask(0o077, fn)
}
