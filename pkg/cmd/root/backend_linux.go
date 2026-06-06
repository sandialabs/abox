//go:build linux

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/helper"
	"github.com/sandialabs/abox/pkg/cmd/mount"
	"github.com/sandialabs/abox/pkg/cmd/unmount"

	// Register the libvirt backend on Linux.
	_ "github.com/sandialabs/abox/internal/backend/libvirt"
)

// addPlatformCommands registers Linux-specific subcommands.
func addPlatformCommands(cmd *cobra.Command) {
	cmd.AddCommand(helper.NewCmdHelper())
}

// addPlatformGroupedCommands is a no-op on Linux; the macOS variant registers
// the `abox teardown-pf` command. Keeping the function declared on both
// platforms lets root.go call it unconditionally.
func addPlatformGroupedCommands(_ *cobra.Command, _ *factory.Factory) {}

// addPlatformFileCommands registers the SSHFS-backed mount/unmount commands.
// These are Linux-only because they depend on FUSE/sshfs, which abox does not
// support on macOS.
func addPlatformFileCommands(cmd *cobra.Command, f *factory.Factory) {
	addGroupedCommand(cmd, mount.NewCmdMount(f, nil), groupFiles)
	addGroupedCommand(cmd, unmount.NewCmdUnmount(f, nil), groupFiles)
}
