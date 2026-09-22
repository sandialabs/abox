//go:build unix

package config

import "syscall"

// lockFileExclusive acquires an exclusive advisory lock on the open file
// descriptor, blocking until it is available.
func lockFileExclusive(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_EX)
}

// unlockFile releases the advisory lock held on the open file descriptor.
func unlockFile(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_UN)
}
