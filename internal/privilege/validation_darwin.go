//go:build darwin

package privilege

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// safePathChars matches strings containing ONLY safe path characters.
// Using an allowlist instead of a denylist to avoid missing dangerous characters
// (e.g., null bytes, newlines, glob characters).
// A literal space is permitted on macOS because abox storage lives under
// "~/Library/Application Support/abox", which contains a space in the path.
// The Linux setuid helper uses a stricter variant (validation_linux.go) that
// excludes spaces, since /var/lib/libvirt/images/abox never contains spaces and
// the helper runs as setuid root where loosening the character set is unacceptable.
var safePathChars = regexp.MustCompile(`^[a-zA-Z0-9/_.\-+:=@ ]+$`)

// aboxStorageSubpath is the per-user storage root suffix used by the macOS
// vfkit backend: <home>/Library/Application Support/abox. VM disks, ISOs, EFI
// stores (images/instances/<name>, images/base/...) all live beneath it
// (see internal/backend/vfkit/backend.go storageDir() and
// internal/config GetPathsWithOptions).
const aboxStorageSubpath = "Library/Application Support/abox"

// Path confinement on macOS mirrors the Linux helper's containment of its
// root-privileged file-op surface (validation_linux.go), with one deliberate
// difference: macOS storage is user-owned, so we drop Linux's TOCTOU/symlink
// *pinning* (O_PATH|O_NOFOLLOW + /proc/self/fd) but keep *containment*. The
// darwin helper runs as root via sudo, so the allowed root cannot be derived
// from the process environment (that would be root's home). Instead, like
// Linux's isAllowedHomePath, we parse "/Users/<name>" from the path itself and
// verify that directory is owned by the invoking user (allowedUID) before
// trusting the "Library/Application Support/abox" suffix beneath it.

// allowedRoot derives the per-user abox storage root from cleanPath and
// verifies the user's home directory is owned by allowedUID. It returns the
// allowed root (".../Library/Application Support/abox") and true on success.
func (s *PrivilegeServer) allowedRoot(cleanPath string) (string, bool) {
	if !strings.HasPrefix(cleanPath, "/Users/") {
		return "", false
	}
	// cleanPath = /Users/<name>/...  ->  parts = ["", "Users", "<name>", rest]
	parts := strings.SplitN(cleanPath, "/", 4)
	if len(parts) < 4 {
		return "", false
	}
	homeDir := "/" + parts[1] + "/" + parts[2]
	if err := s.verifyDirOwnership(homeDir); err != nil {
		return "", false
	}
	return filepath.Join(homeDir, aboxStorageSubpath), true
}

// verifyDirOwnership checks that dir exists and is owned by s.allowedUID.
// Local darwin copy of the Linux helper's identically named function (which
// lives in a linux-tagged file) so the parity logic stays self-contained.
func (s *PrivilegeServer) verifyDirOwnership(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("cannot verify directory ownership: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(s.allowedUID) { //nolint:gosec // UID is always non-negative
		return fmt.Errorf("directory %s not owned by allowed UID %d", dir, s.allowedUID)
	}
	return nil
}

// confine returns nil if cleanPath is under the allowed root, else an error.
// Helper shared by the validators below.
func (s *PrivilegeServer) confine(cleanPath string) error {
	root, ok := s.allowedRoot(cleanPath)
	if !ok {
		return fmt.Errorf("path not in allowed paths: %s", cleanPath)
	}
	if cleanPath == root || strings.HasPrefix(cleanPath, root+"/") {
		return nil
	}
	return fmt.Errorf("path not in allowed paths: %s", cleanPath)
}

// ValidatePath checks that path is within the per-user abox storage root and
// contains no traversal. Mirrors the Linux ValidatePath (validation_linux.go),
// but the root is per-user and ownership-verified rather than a fixed constant.
func (s *PrivilegeServer) ValidatePath(path string) error {
	// Reject traversal in the raw path...
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed: %s", path)
	}

	cleanPath := filepath.Clean(path)

	// ...and after cleaning (belt and suspenders).
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal not allowed: %s", path)
	}

	return s.confine(cleanPath)
}

// ValidatePathNoSymlinks validates a path and ensures no symlink in the path
// could escape the allowed root once resolved. Mirrors the Linux variant: the
// macOS storage being user-owned only justifies dropping TOCTOU *pinning*, not
// the symlink-escape *containment* check.
func (s *PrivilegeServer) ValidatePathNoSymlinks(path string) error {
	if err := s.ValidatePath(path); err != nil {
		return err
	}

	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		// If the path doesn't exist yet, walk up to the first existing ancestor.
		if os.IsNotExist(err) {
			return s.validateNonExistentPath(path)
		}
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	if err := s.confine(filepath.Clean(realPath)); err != nil {
		return fmt.Errorf("resolved path escapes allowed directory: %s -> %s", path, realPath)
	}
	return nil
}

// validateNonExistentPath validates a not-yet-existing path by walking up the
// directory tree until it finds an existing ancestor, then confining that
// ancestor's resolved path. Mirrors the Linux validateNonExistentPath.
func (s *PrivilegeServer) validateNonExistentPath(path string) error {
	current := path
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("cannot verify path safety (no existing ancestor in allowed paths): %s", path)
		}

		realParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			if os.IsNotExist(err) {
				current = parent
				continue
			}
			return fmt.Errorf("failed to resolve ancestor path: %w", err)
		}

		cleanParent := filepath.Clean(realParent)
		root, ok := s.allowedRoot(cleanParent)
		if ok && (cleanParent == root || strings.HasPrefix(cleanParent, root+"/") || strings.HasPrefix(root, cleanParent+"/")) {
			return nil
		}
		return fmt.Errorf("resolved ancestor path escapes allowed directory: %s -> %s", parent, realParent)
	}
}

// removeAllMinComponents is the minimum number of path components a RemoveAll
// target must have. The allowed root "/Users/<name>/Library/Application
// Support/abox" is 5 components (Users, <name>, Library, "Application Support",
// abox); requiring strictly more prevents removing the root itself or any of
// its ancestors. Mirrors the Linux ValidateRemoveAllPath depth guard.
const removeAllMinComponents = 6

// ValidateRemoveAllPath validates a path for RemoveAll: it must be confined to
// the allowed root AND deeper than the root itself. Mirrors the Linux variant.
func (s *PrivilegeServer) ValidateRemoveAllPath(path string) error {
	if err := s.ValidatePath(path); err != nil {
		return err
	}

	cleanPath := filepath.Clean(path)
	nonEmpty := 0
	for c := range strings.SplitSeq(cleanPath, "/") {
		if c != "" {
			nonEmpty++
		}
	}

	if nonEmpty < removeAllMinComponents {
		return fmt.Errorf("remove_all requires path with at least %d components (got %d): %s",
			removeAllMinComponents, nonEmpty, path)
	}

	return nil
}
