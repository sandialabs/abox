//go:build linux

package privilege

import (
	"os/exec"
	"syscall"
)

// platformSafeCommand applies Linux-specific process attributes.
// Sets explicit root credentials so child processes run with ruid=0/euid=0
// even when the helper itself is a setuid binary (euid=0 but ruid=calling-user).
// Without this, iptables-nft fails because its netlink backend checks the real UID.
func platformSafeCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
}
