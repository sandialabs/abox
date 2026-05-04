package privilege

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// libvirtImagesDir is the privileged-helper-managed disk image storage root.
// Mirrors config.LibvirtImagesDir; kept local to avoid importing config from
// the privilege helper, which must be a leaf package for the setuid binary.
const libvirtImagesDir = "/var/lib/libvirt/images/abox"

// Allowed base paths for privileged operations.
var allowedPaths = []string{
	libvirtImagesDir,
}

// safePathChars matches strings containing ONLY safe path characters.
// Using an allowlist instead of a denylist to avoid missing dangerous characters
// (e.g., null bytes, newlines, glob characters).
var safePathChars = regexp.MustCompile(`^[a-zA-Z0-9/_.\-+:=@]+$`)

// safeBridgeChars matches strings containing ONLY valid bridge name characters.
var safeBridgeChars = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

// validChmodMode matches 3-4 octal digit file modes.
var validChmodMode = regexp.MustCompile(`^[0-7]{3,4}$`)

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
// Requires at least 5 path components to prevent accidental deletion of important directories.
func ValidateRemoveAllPath(path string) error {
	// First, validate it's in the allowed paths
	if err := ValidatePath(path); err != nil {
		return err
	}

	// Count path components (require at least 5: /, var, lib, libvirt, images, abox, <name>)
	cleanPath := filepath.Clean(path)
	components := strings.Split(cleanPath, "/")
	// Filter out empty strings from leading /
	nonEmpty := 0
	for _, c := range components {
		if c != "" {
			nonEmpty++
		}
	}

	// /var/lib/libvirt/images/abox = 5 components, need at least one more
	if nonEmpty < 6 {
		return fmt.Errorf("remove_all requires path with at least 6 components (got %d): %s", nonEmpty, path)
	}

	return nil
}

// ValidateArgs checks that arguments contain only safe characters.
// Uses a positive allowlist rather than a denylist to ensure no dangerous
// characters (null bytes, newlines, shell metacharacters, etc.) slip through.
func ValidateArgs(args []string) error {
	for _, arg := range args {
		if arg == "" {
			continue
		}
		if !safePathChars.MatchString(arg) {
			return fmt.Errorf("argument contains disallowed characters: %s", arg)
		}
	}
	return nil
}

// ValidateBridgeName validates a bridge interface name.
// Must start with "abox-" or "ab-" prefix (ab- is used for hashed names
// when instance names are too long for the 15-char Linux bridge limit).
func ValidateBridgeName(name string) error {
	if !strings.HasPrefix(name, "abox-") && !strings.HasPrefix(name, "ab-") {
		return fmt.Errorf("bridge name must start with 'abox-' or 'ab-': %s", name)
	}

	// Linux bridge names are limited to IFNAMSIZ (16 bytes including null terminator = 15 chars)
	if len(name) > 15 {
		return fmt.Errorf("bridge name exceeds 15-character Linux limit: %s", name)
	}

	// Check for invalid characters (allowlist: alphanumeric and hyphen only)
	if !safeBridgeChars.MatchString(name) {
		return fmt.Errorf("bridge name contains invalid characters: %s", name)
	}

	return nil
}

// ValidateSocketPath validates a socket path argument.
// The path must be absolute and clean (no "..", trailing slashes, etc.).
// Used by both the setuid binary and the cobra helper subcommand.
func ValidateSocketPath(socketPath string) error {
	if socketPath == "" {
		return errors.New("socket path is required")
	}

	cleaned := filepath.Clean(socketPath)
	if cleaned != socketPath {
		return errors.New("socket path must be clean (no .., trailing slashes, etc.)")
	}
	if !filepath.IsAbs(cleaned) {
		return errors.New("socket path must be an absolute path")
	}

	return nil
}

// ValidateChmodMode validates a file mode string.
func ValidateChmodMode(mode string) error {
	// Allow only numeric modes (e.g., "644", "755")
	if !validChmodMode.MatchString(mode) {
		return fmt.Errorf("invalid chmod mode: %s (must be 3-4 octal digits)", mode)
	}
	return nil
}
