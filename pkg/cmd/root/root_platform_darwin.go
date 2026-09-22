//go:build darwin

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/mount"
	mountremove "github.com/sandialabs/abox/pkg/cmd/mount/remove"
	"github.com/sandialabs/abox/pkg/cmd/teardownpf"
)

// registerPlatformCommands registers OS-specific subcommands. On macOS the
// SSHFS-based mount command group and the top-level unmount alias (mount remove)
// are registered (they require a FUSE + sshfs install — the kext-less fuse-t is
// recommended; see `abox help quickstart`). We also register teardown-pf, which
// removes the abox anchor references the privilege helper wires into
// /etc/pf.conf on first start.
func registerPlatformCommands(cmd *cobra.Command, f *factory.Factory) {
	addGroupedCommand(cmd, mount.NewCmdMount(f), groupFiles)
	addGroupedCommand(cmd, mountremove.NewCmdUnmount(f, nil), groupFiles)
	addGroupedCommand(cmd, teardownpf.NewCmdTeardownPF(f, nil), groupUtilities)
}
