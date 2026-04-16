//go:build darwin

package privilege

import "os/exec"

// platformSafeCommand applies macOS-specific process attributes.
// On macOS, the helper is launched via sudo which already sets the real UID to 0,
// so no explicit credential override is needed.
func platformSafeCommand(cmd *exec.Cmd) {
	// No platform-specific attributes needed on macOS.
	_ = cmd
}
