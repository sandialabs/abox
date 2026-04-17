//go:build linux

package root

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/helper"
	"github.com/spf13/cobra"

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
