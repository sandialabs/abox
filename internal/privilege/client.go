package privilege

import (
	"fmt"
	"os"
	"syscall"
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
		// be executed via sudo/pkexec with elevated privileges.
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if stat.Uid != 0 {
			return "", fmt.Errorf("abox binary %s not owned by root (uid %d)", loc, stat.Uid)
		}
		return loc, nil
	}

	return "", os.ErrNotExist
}
