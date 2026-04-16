//go:build darwin

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/helper"

	// Register the macOS backend on darwin.
	_ "github.com/sandialabs/abox/internal/backend/darwin"
)

// addPlatformCommands registers macOS-specific subcommands.
func addPlatformCommands(cmd *cobra.Command) {
	cmd.AddCommand(helper.NewCmdHelper())
}
