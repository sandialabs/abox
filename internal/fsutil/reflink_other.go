//go:build !linux

package fsutil

import (
	"errors"
	"os"
)

// reflinkClone is unsupported off Linux; CopyFile falls back to a buffered copy.
func reflinkClone(_, _ *os.File) error {
	return errors.New("reflink not supported on this platform")
}
