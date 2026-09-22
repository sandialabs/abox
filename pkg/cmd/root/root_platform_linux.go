//go:build linux

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/mount"
	mountremove "github.com/sandialabs/abox/pkg/cmd/mount/remove"
)

// registerPlatformCommands registers OS-specific subcommands. On Linux this adds
// the SSHFS-based mount command group and the top-level unmount alias
// (mount remove). teardown-pf is macOS-only and is not registered here.
func registerPlatformCommands(cmd *cobra.Command, f *factory.Factory) {
	addGroupedCommand(cmd, mount.NewCmdMount(f), groupFiles)
	addGroupedCommand(cmd, mountremove.NewCmdUnmount(f, nil), groupFiles)
}
