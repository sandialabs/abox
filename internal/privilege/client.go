package privilege

import (
	"fmt"
	"os"

	"github.com/sandialabs/abox/internal/sysutil"
)

// FindAboxBinary finds the abox binary securely.
func FindAboxBinary() (string, error) {
	if execPath, err := os.Executable(); err == nil {
		return execPath, nil
	}

	trustedLocations := []string{
		"/usr/local/bin/abox",
		"/usr/bin/abox",
	}

	for _, loc := range trustedLocations {
		info, err := os.Lstat(loc)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		// Defense-in-depth: verify root ownership for binaries that will
		// be executed via sudo/pkexec with elevated privileges. If ownership
		// cannot be determined (unsupported platform), fail closed by skipping
		// this candidate rather than trusting an unverifiable binary.
		uidOwner, _, ok := sysutil.FileOwner(info)
		if !ok {
			continue
		}
		if uidOwner != 0 {
			return "", fmt.Errorf("abox binary %s not owned by root (uid %d)", loc, uidOwner)
		}
		return loc, nil
	}

	return "", os.ErrNotExist
}
