package privilege

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

const (
	escalationSudo   = "sudo"
	escalationPkexec = "pkexec"
)

// SelectEscalationTool returns "pkexec" or "sudo" based on the environment.
// On headless systems (no DISPLAY/WAYLAND_DISPLAY), prefers sudo since
// pkexec requires a polkit agent. Returns an error if no tool is available.
func SelectEscalationTool() (string, error) {
	// Override via env var
	if method := os.Getenv("ABOX_PRIVILEGE_METHOD"); method != "" {
		if method != escalationSudo && method != escalationPkexec {
			return "", fmt.Errorf("ABOX_PRIVILEGE_METHOD must be 'sudo' or 'pkexec', got %q", method)
		}
		if _, err := exec.LookPath(method); err != nil {
			return "", fmt.Errorf("ABOX_PRIVILEGE_METHOD=%s but %s not found", method, method)
		}
		return method, nil
	}

	// Auto-detect: on headless systems, prefer sudo (pkexec needs polkit agent)
	hasDisplay := os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	_, pkexecErr := exec.LookPath(escalationPkexec)
	_, sudoErr := exec.LookPath(escalationSudo)

	if hasDisplay && pkexecErr == nil {
		return escalationPkexec, nil
	}
	if sudoErr == nil {
		return escalationSudo, nil
	}
	if pkexecErr == nil {
		return escalationPkexec, nil // Last resort, may fail on headless
	}
	return "", errors.New("no privilege escalation tool available (need pkexec or sudo)")
}
