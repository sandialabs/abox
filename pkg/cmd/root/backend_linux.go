//go:build linux

package root

import (
	"github.com/sandialabs/abox/pkg/cmd/helper"
	"github.com/spf13/cobra"

	// Register the libvirt backend on Linux.
	_ "github.com/sandialabs/abox/internal/backend/libvirt"
)

// addPlatformCommands registers Linux-specific subcommands.
func addPlatformCommands(cmd *cobra.Command) {
	cmd.AddCommand(helper.NewCmdHelper())
}
