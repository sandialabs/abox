//go:build darwin

package privilege

import "os/exec"

// platformSafeCommand is a no-op on darwin. The macOS pf helper is spawned via
// sudo, so the process (and therefore its children) already runs with ruid=0;
// no credential override is needed. pfctl does not check the real UID the way
// iptables-nft does. Returning nil keeps the shared safeCommand signature.
func platformSafeCommand(_ *exec.Cmd) error {
	return nil
}

// safeCommand creates an exec.Cmd for pfctl with an explicit minimal environment
// (safeEnv). Every darwin caller targets pfctl, so the binary is fixed here
// rather than passed in. platformSafeCommand is a no-op on darwin but is still
// invoked to keep the seam symmetric with Linux.
func safeCommand(args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(pfctlPath, args...)
	cmd.Env = safeEnv
	if err := platformSafeCommand(cmd); err != nil {
		return nil, err
	}
	return cmd, nil
}
