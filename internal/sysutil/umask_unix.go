//go:build unix

package sysutil

import "syscall"

// WithRestrictiveUmask runs fn with the process umask set to 0o077, restoring
// the previous umask afterward. This ensures files/sockets created inside fn are
// owner-only, closing the race window between creation and an explicit chmod.
//
// The umask is process-global, so callers should keep fn short and must not rely
// on concurrent goroutines observing a particular umask while fn runs.
func WithRestrictiveUmask(fn func()) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	fn()
}
