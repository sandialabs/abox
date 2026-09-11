package images

import (
	"fmt"
	"io"
	"os"
)

// LockMode selects the kind of advisory lock taken on a base image file. It is a
// capability-level abstraction so callers do not depend on Linux flock
// constants; the platform seam (lock_unix.go / lock_other.go) maps it to the
// underlying primitive.
type LockMode int

const (
	// LockShared allows concurrent readers (e.g. multiple instance creates
	// cloning from the same base image) while blocking an exclusive holder.
	LockShared LockMode = iota
	// LockExclusive is taken by base-image removal so it waits for in-flight
	// creates to finish and blocks new ones until the remove completes.
	LockExclusive
)

// lockCloser wraps a file descriptor and releases the lock on Close.
type lockCloser struct {
	f *os.File
}

func (l *lockCloser) Close() error {
	defer l.f.Close()
	return unlockFile(l.f)
}

// LockBaseImage acquires an advisory lock on a base image file and returns an
// io.Closer that releases it. On platforms without advisory file locking the
// lock is a no-op (see lock_other.go for why that is acceptable there).
func LockBaseImage(path string, mode LockMode) (io.Closer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open base image for locking: %w", err)
	}

	if err := lockFile(f, mode); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to acquire lock on base image: %w", err)
	}

	return &lockCloser{f: f}, nil
}
