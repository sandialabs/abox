//go:build linux

package images

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// lockCloser wraps a file descriptor and releases the flock on Close.
type lockCloser struct {
	f *os.File
}

func (l *lockCloser) Close() error {
	defer l.f.Close()
	return syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) //nolint:gosec // fd from os.File, safe conversion
}

// LockBaseImage acquires a flock on a base image file.
// Returns an io.Closer that releases the lock.
// lockType should be syscall.LOCK_SH (shared) or syscall.LOCK_EX (exclusive).
func LockBaseImage(path string, lockType int) (io.Closer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open base image for locking: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), lockType); err != nil { //nolint:gosec // fd from os.File, safe conversion
		f.Close()
		return nil, fmt.Errorf("failed to acquire lock on base image: %w", err)
	}

	return &lockCloser{f: f}, nil
}
