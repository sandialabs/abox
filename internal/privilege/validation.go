package privilege

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// safeBridgeChars matches strings containing ONLY valid bridge name characters.
var safeBridgeChars = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

// safeVMNetName matches VMware host-only/NAT interface names (e.g. "vmnet2"),
// which are not created by abox and so lack the abox-/ab- prefix.
var safeVMNetName = regexp.MustCompile(`^vmnet[0-9]+$`)

// ValidateBridgeName validates a bridge interface name.
// Must start with "abox-" or "ab-" prefix (ab- is used for hashed names
// when instance names are too long for the 15-char Linux bridge limit), or be a
// VMware vmnet interface name ("vmnetN") used by the VMware backend.
func ValidateBridgeName(name string) error {
	if !strings.HasPrefix(name, "abox-") && !strings.HasPrefix(name, "ab-") && !safeVMNetName.MatchString(name) {
		return fmt.Errorf("bridge name must start with 'abox-' or 'ab-', or be a 'vmnetN' name: %s", name)
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
