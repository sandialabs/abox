//go:build !linux

package privilege

import (
	"errors"
	"os/exec"
)

// ErrRootCredentialUnsupported is returned by setRootCredential off Linux. The
// setuid privilege helper is a Linux-only mechanism (it manipulates iptables via
// netlink and relies on setuid + explicit root credentials), so there is no safe
// non-Linux behavior: the caller must fail closed rather than spawn a child with
// the wrong (calling-user) credentials against a privileged operation.
var ErrRootCredentialUnsupported = errors.New("root credential for privileged child processes is not supported on this platform")

// setRootCredential fails closed on non-Linux platforms.
func setRootCredential(_ *exec.Cmd) error {
	return ErrRootCredentialUnsupported
}
