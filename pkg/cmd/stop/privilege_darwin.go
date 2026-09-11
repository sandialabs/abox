//go:build darwin

package stop

import "github.com/sandialabs/abox/pkg/cmd/factory"

// configureStopPrivilege gates privilege on the TTY on macOS. Unlike Linux there
// is no setuid helper: the pf anchor flush can only escalate via interactive sudo.
// Forcing non-interactive (as Linux does) would make `PfBase.Remove` fail to
// acquire the helper and only warn, leaving the per-instance `abox/<name>` anchor
// loaded in the kernel after every `abox stop` (a leak that accumulates across
// stops). Gating on the TTY lets an interactive stop prompt and flush cleanly —
// matching `abox remove`/`teardown-pf` — while a non-TTY run (CI/scripts/pipes)
// stays best-effort so stop never hangs on a password prompt.
func configureStopPrivilege(f *factory.Factory) {
	f.SetNonInteractivePrivilegeFromTTY()
}
