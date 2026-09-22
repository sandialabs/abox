//go:build !linux && !darwin

package stop

import "github.com/sandialabs/abox/pkg/cmd/factory"

// configureStopPrivilege forces non-interactive privilege on platforms without a
// VM backend (e.g. Windows): there is no egress enforcement to tear down, so the
// choice is moot, and this keeps stop from ever blocking on a prompt.
func configureStopPrivilege(f *factory.Factory) {
	f.SetNonInteractivePrivilege(true)
}
