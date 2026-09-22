//go:build !unix

package sysutil

// WithRestrictiveUmask simply runs fn on platforms without a umask (Windows):
// access control there relies on the parent directory's ACL and, for the
// privileged transport, on the peer-credential check (which is unsupported on
// non-Linux, so that transport is not usable there). Any socket/file created by
// fn must be secured by other means on such platforms.
func WithRestrictiveUmask(fn func()) {
	fn()
}
