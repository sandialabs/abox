//go:build !linux && !darwin

package unmount

import "errors"

// doUnmount is unsupported off Linux/macOS (currently Windows): abox's
// SSHFS-based mount/unmount commands are not registered there, but this stub
// keeps the package compiling for the cross-platform build gate.
func doUnmount(_ string, _ bool) error {
	return errors.New("unmount is not supported on this platform")
}
