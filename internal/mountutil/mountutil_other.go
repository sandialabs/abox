//go:build !unix

// Package mountutil provides small cross-platform helpers for working with
// filesystem mounts on the host.
package mountutil

// IsMounted is unsupported off unix (currently Windows): there is no portable
// st_dev comparison, and abox's mount/unmount commands are not offered there.
// It conservatively reports false so callers never treat an unknown state as
// "mounted".
func IsMounted(_ string) bool {
	return false
}

// State mirrors IsMounted's conservative stance off unix: with no portable
// st_dev comparison every path reads as not mounted.
func State(_ string) (MountState, error) {
	return StateNotMounted, nil
}
