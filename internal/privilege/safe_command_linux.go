//go:build linux

package privilege

import "os/exec"

// platformSafeCommand applies the Linux credential setup for a privileged child
// process: explicit root credentials (ruid=0/euid=0). The setuid egress helper
// runs with euid=0 but ruid=calling-user, and iptables-nft's netlink backend
// checks the real UID, so this is required for iptables to succeed.
func platformSafeCommand(cmd *exec.Cmd) error {
	return setRootCredential(cmd)
}

// safeCommand creates an exec.Cmd with an explicit minimal environment (safeEnv)
// and Linux credential setup (platformSafeCommand). name varies by caller
// (iptablesPath), so it is passed in. If root credentials cannot be applied it
// returns an error and no command, so callers fail closed rather than run a
// privileged tool with the wrong credentials.
func safeCommand(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = safeEnv
	if err := platformSafeCommand(cmd); err != nil {
		return nil, err
	}
	return cmd, nil
}
