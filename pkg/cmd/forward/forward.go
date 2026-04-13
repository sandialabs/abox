package forward

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/forward/add"
	forwardlist "github.com/sandialabs/abox/pkg/cmd/forward/list"
	"github.com/sandialabs/abox/pkg/cmd/forward/remove"
	"github.com/sandialabs/abox/pkg/cmd/forward/restart"

	"github.com/spf13/cobra"
)

// NewCmdForward creates a new forward command.
func NewCmdForward(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "forward",
		Short: "Manage port forwards",
		Long:  `Manage port forwards from host to VM using SSH tunnels.`,
	}

	cmd.AddCommand(add.NewCmdAdd(f, nil))
	cmd.AddCommand(remove.NewCmdRemove(f, nil))
	cmd.AddCommand(forwardlist.NewCmdList(f, nil))
	cmd.AddCommand(restart.NewCmdRestart(f, nil))

	return cmd
}
