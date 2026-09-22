//go:build linux

package stop

import "github.com/sandialabs/abox/pkg/cmd/factory"

// configureStopPrivilege forces non-interactive privilege on Linux: teardown is
// best-effort even on a TTY. Linux's escalation paths (setuid helper, root,
// external helper via ABOX_PRIVILEGE_SOCKET, or an already-running helper) are all
// non-interactive, so the egress flush still succeeds without a prompt; if none is
// available it is skipped rather than blocking on a password. The VM is already
// stopped, so any leftover iptables rules are inert and re-created on next start.
func configureStopPrivilege(f *factory.Factory) {
	f.SetNonInteractivePrivilege(true)
}
