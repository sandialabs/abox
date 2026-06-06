//go:build linux

package privilege

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// libvirtImagesDir is the privileged-helper-managed disk image storage root.
// Mirrors config.LibvirtImagesDir; kept local to avoid importing config from
// the privilege helper, which must be a leaf package for the setuid binary.
const libvirtImagesDir = "/var/lib/libvirt/images/abox"

// allowedPaths lists the base directories for privileged file operations on Linux.
// Operations (chmod, mkdir, remove, copy) are restricted to paths under these directories.
var allowedPaths = []string{
	libvirtImagesDir,
}

// ValidatePath checks if a path is within the allowed paths.
// Returns an error if the path is not allowed.
func ValidatePath(path string) error {
	// Check for path traversal attempts in original path
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed: %s", path)
	}

	// Clean the path to normalize it
	cleanPath := filepath.Clean(path)

	// Check for traversal in cleaned path too (belt and suspenders)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal not allowed: %s", path)
	}

	// Verify the path is under an allowed base
	allowed := false
	for _, base := range allowedPaths {
		if strings.HasPrefix(cleanPath, base+"/") || cleanPath == base {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("path not in allowed paths: %s", path)
	}

	return nil
}

// ValidatePathNoSymlinks validates a path and ensures no symlinks in the path
// could escape the allowed directory. This is critical for operations that
// modify files (chmod, write, delete).
func ValidatePathNoSymlinks(path string) error {
	// First do basic validation
	if err := ValidatePath(path); err != nil {
		return err
	}

	// Resolve the real path (follows all symlinks)
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		// If path doesn't exist yet, walk up until we find an existing ancestor
		if os.IsNotExist(err) {
			return validateNonExistentPath(path)
		}
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Validate the resolved path
	for _, base := range allowedPaths {
		if strings.HasPrefix(realPath, base+"/") || realPath == base {
			return nil
		}
	}

	return fmt.Errorf("resolved path escapes allowed directory: %s -> %s", path, realPath)
}

// validateNonExistentPath validates a path that doesn't exist yet by walking
// up the directory tree until finding an existing ancestor.
func validateNonExistentPath(path string) error {
	current := path
	for {
		parent := filepath.Dir(current)
		if parent == current {
			// Reached root without finding existing directory
			return fmt.Errorf("cannot verify path safety (no existing ancestor in allowed paths): %s", path)
		}

		realParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			if os.IsNotExist(err) {
				// Parent doesn't exist, keep walking up
				current = parent
				continue
			}
			return fmt.Errorf("failed to resolve ancestor path: %w", err)
		}

		// Found an existing ancestor - validate it
		for _, base := range allowedPaths {
			if strings.HasPrefix(realParent, base+"/") || realParent == base || strings.HasPrefix(base, realParent+"/") {
				return nil
			}
		}
		return fmt.Errorf("resolved ancestor path escapes allowed directory: %s -> %s", parent, realParent)
	}
}

// ValidateRemoveAllPath validates a path for RemoveAll operations.
// Requires at least 6 path components to prevent accidental deletion of important directories.
// /var/lib/libvirt/images/abox = 5 components, need at least one more.
func ValidateRemoveAllPath(path string) error {
	// First, validate it's in the allowed paths
	if err := ValidatePath(path); err != nil {
		return err
	}

	// Count path components
	cleanPath := filepath.Clean(path)
	components := strings.Split(cleanPath, "/")
	// Filter out empty strings from leading /
	nonEmpty := 0
	for _, c := range components {
		if c != "" {
			nonEmpty++
		}
	}

	if nonEmpty < 6 {
		return fmt.Errorf("remove_all requires path with at least 6 components (got %d): %s", nonEmpty, path)
	}

	return nil
}
