//go:build linux

package privilege

import (
	"os/exec"
	"syscall"
)

// setRootCredential configures cmd so the spawned child runs with real and
// effective uid/gid 0. This is required when the setuid helper (euid=0,
// ruid=calling-user) execs iptables: iptables-nft's netlink backend checks the
// REAL uid, so without an explicit root credential the child would fail. It is a
// Linux-only capability tied to the setuid privilege helper.
func setRootCredential(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 0, Gid: 0},
	}
	return nil
}
