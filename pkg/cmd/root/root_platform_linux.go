//go:build linux

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/mount"
	"github.com/sandialabs/abox/pkg/cmd/unmount"
)

// registerPlatformCommands registers OS-specific subcommands. On Linux this adds
// the SSHFS-based mount/unmount commands. teardown-pf is macOS-only and is not
// registered here.
func registerPlatformCommands(cmd *cobra.Command, f *factory.Factory) {
	addGroupedCommand(cmd, mount.NewCmdMount(f, nil), groupFiles)
	addGroupedCommand(cmd, unmount.NewCmdUnmount(f, nil), groupFiles)
}
