package net

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/net/filter"
	"github.com/sandialabs/abox/pkg/cmd/net/profile"

	"github.com/spf13/cobra"
)

// NewCmdNet creates the net command with subcommands for network management.
func NewCmdNet(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "net <command>",
		Short: "Manage instance network filtering",
		Long: `Manage network filtering for instances.

Controls DNS and HTTP filtering behavior. Use 'filter' to switch between
active mode (block unlisted domains) and passive mode (log only), and
'profile' to review domains captured during passive mode.`,
	}

	cmd.AddCommand(filter.NewCmdFilter(f, nil))
	cmd.AddCommand(profile.NewCmdProfile(f, nil))

	return cmd
}
