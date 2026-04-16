//go:build linux

package config

import (
	"fmt"
	"os"
)

// runtimeDirFallback returns the default runtime directory on Linux.
func runtimeDirFallback() string {
	return fmt.Sprintf("/run/user/%d", os.Getuid())
}
