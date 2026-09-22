//go:build unix

package images

import (
	"os"
	"syscall"
)

// lockFile takes an advisory flock on f in the requested mode (blocking).
func lockFile(f *os.File, mode LockMode) error {
	how := syscall.LOCK_SH
	if mode == LockExclusive {
		how = syscall.LOCK_EX
	}
	return syscall.Flock(int(f.Fd()), how)
}

// unlockFile releases the advisory flock held on f.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
