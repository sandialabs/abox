//go:build unix

package procutil

import (
	"os/exec"
	"syscall"
)

// Detach configures cmd so the spawned child starts in its own process group,
// decoupling it from the parent's controlling terminal and signal delivery
// (Setpgid). This is what lets abox spawn long-lived filter/monitor daemons that
// survive the launching command.
func Detach(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}
