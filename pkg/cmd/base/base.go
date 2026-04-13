package base

import (
	"github.com/sandialabs/abox/pkg/cmd/base/importcmd"
	baselist "github.com/sandialabs/abox/pkg/cmd/base/list"
	"github.com/sandialabs/abox/pkg/cmd/base/pull"
	baseremove "github.com/sandialabs/abox/pkg/cmd/base/remove"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// NewCmdBase creates a new base command.
func NewCmdBase(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "base",
		Short: "Manage base images",
		Long: `Manage base images used to create abox instances.

Base images are the starting disk images for new VMs. Use 'base list' to see
available images, 'base pull' to download them, and 'base import' to add
local images.`,
	}

	cmd.AddCommand(baselist.NewCmdList(f, nil))
	cmd.AddCommand(pull.NewCmdPull(f, nil))
	cmd.AddCommand(importcmd.NewCmdImport(f, nil))
	cmd.AddCommand(baseremove.NewCmdRemove(f, nil))

	return cmd
}
