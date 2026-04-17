//go:build darwin

package root

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/helper"
	"github.com/sandialabs/abox/pkg/cmd/teardownpf"

	// Register the macOS backend on darwin.
	_ "github.com/sandialabs/abox/internal/backend/darwin"
)

// addPlatformCommands registers macOS-specific subcommands.
func addPlatformCommands(cmd *cobra.Command) {
	cmd.AddCommand(helper.NewCmdHelper())
}

// addPlatformGroupedCommands registers macOS-only commands that belong in a
// help group (currently just teardown-pf in the utilities group).
func addPlatformGroupedCommands(cmd *cobra.Command, f *factory.Factory) {
	addGroupedCommand(cmd, teardownpf.NewCmdTeardownPF(f, nil), groupUtilities)
}
