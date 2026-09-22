// Package fsutil holds small filesystem helpers shared across abox.
package fsutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// copyContents streams src into dst with a 1 MiB buffer (fewer syscalls than the
// 32 KiB io.Copy default). A package var so a fault-injection test can force a
// mid-copy error on the fallback path.
var copyContents = func(dst io.Writer, src io.Reader) error {
	buf := make([]byte, 1<<20)
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

// reflink is the copy-on-write fast path (indirected via a var so a test can
// force the buffered fallback regardless of the underlying filesystem).
var reflink = reflinkClone

// CopyFile copies a regular file from src to dst. The source must be a regular
// file (symlinks, devices and FIFOs are rejected, e.g. from a crafted import
// archive). It uses a copy-on-write reflink fast path where the filesystem
// supports it (btrfs/xfs — near-instant, no extra space for a multi-GB image),
// falling back to a buffered byte copy otherwise.
//
// The write is atomic and durable: contents are written to a temp file in dst's
// directory, fsync'd, then renamed over dst (and the parent directory is fsync'd
// so the rename itself survives a crash), so a crash or a mid-copy failure never
// leaves a partial or truncated dst — either the old dst survives or the new one
// appears whole. On any error the temp file is removed. The destination inherits
// the source file's permission bits (so a 0600 disk image is not silently widened
// on copy); callers that need a different mode chmod afterwards. Note that when
// dst already exists this replaces it (and its mode) rather than truncating it in
// place.
func CopyFile(src, dst string) error {
	// Lstat (not Stat) so a symlinked src is rejected rather than followed.
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file: %s", src)
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Temp file in the SAME directory as dst so the final rename is atomic (a
	// cross-directory rename would not be, and could fail with EXDEV).
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".copy-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// Remove the temp on any error path; a no-op once the rename has consumed it.
	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	// Fast path: reflink (FICLONE). Fails cleanly (EXDEV/EOPNOTSUPP) when
	// unsupported, in which case we fall back to a buffered copy.
	if err := reflink(tmp, in); err != nil {
		if err := copyContents(tmp, in); err != nil {
			return err
		}
	}

	// Match the destination's mode to the source file's permission bits. CreateTemp
	// makes the temp 0600; neither reflink (FICLONE clones data, not mode) nor the
	// buffered fallback copies the mode, so set it explicitly. This avoids silently
	// widening a 0600 image to world-rw on copy (e.g. an exported snapshot written
	// to a user-chosen path outside the 0700 storage tree).
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	success = true

	// fsync the parent directory so the rename (the directory entry update) is
	// durable across a crash, not just the file contents. Best-effort: a failure
	// here does not undo the completed copy, and some filesystems reject dir sync.
	if d, err := os.Open(filepath.Dir(dst)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
