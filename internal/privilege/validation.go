package privilege

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// safePathChars is defined per-platform in validation_linux.go and
// validation_darwin.go because the allowed character set differs:
// macOS abox storage lives under "~/Library/Application Support/abox",
// which contains a space, while the Linux setuid helper keeps the strict set.

// safeBridgeChars matches strings containing ONLY valid bridge name characters.
var safeBridgeChars = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

// validChmodMode matches 3-4 octal digit file modes.
var validChmodMode = regexp.MustCompile(`^[0-7]{3,4}$`)

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
