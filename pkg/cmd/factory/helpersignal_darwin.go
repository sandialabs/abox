//go:build darwin

package factory

import "github.com/sandialabs/abox/internal/vmnethelper"

// ConfigureInteractiveHelperSignaling lets the vmnet-helper teardown fall back to an
// interactive `sudo kill` prompt when attached to a terminal. On macOS ≤15 the helper
// is root-owned, so a non-interactive `sudo -n kill` fails unless the operator granted
// passwordless kill; enabling the interactive fallback lets stop/remove/down prompt for
// the password once (reusing sudo's credential cache for the pf-anchor teardown) instead
// of requiring a broad passwordless-kill sudoers grant. Non-TTY runs stay best-effort.
// Commands call this before signalling the helper.
func (f *Factory) ConfigureInteractiveHelperSignaling() {
	vmnethelper.SetInteractiveSignaling(f.IO.IsTerminal())
}
