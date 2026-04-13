package config

import (
	"github.com/sandialabs/abox/pkg/cmd/config/edit"
	"github.com/sandialabs/abox/pkg/cmd/config/view"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// NewCmdConfig creates a new config command.
func NewCmdConfig(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "View and edit instance configuration",
		Long:  `View and edit instance configuration settings.`,
	}

	cmd.AddCommand(view.NewCmdView(f, nil))
	cmd.AddCommand(edit.NewCmdEdit(f, nil))

	return cmd
}
