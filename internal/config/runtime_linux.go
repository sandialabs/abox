//go:build linux

package config

import (
	"fmt"
	"os"
)

// runtimeDirFallback returns the default per-user runtime directory on Linux
// when XDG_RUNTIME_DIR is unset. systemd creates /run/user/<uid> at login with
// mode 0700 owned by the user, which is the secure location for helper sockets.
func runtimeDirFallback() string {
	return fmt.Sprintf("/run/user/%d", os.Getuid())
}
