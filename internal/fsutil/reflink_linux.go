//go:build linux

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// reflinkClone attempts a copy-on-write clone of src into dst via the FICLONE
// ioctl. Returns an error (leaving dst empty) when the filesystem does not
// support it.
func reflinkClone(dst, src *os.File) error {
	return unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
}
