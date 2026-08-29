package mount

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/mount/add"
	mountlist "github.com/sandialabs/abox/pkg/cmd/mount/list"
	"github.com/sandialabs/abox/pkg/cmd/mount/remove"

	"github.com/spf13/cobra"
)

// NewCmdMount creates a new mount command.
func NewCmdMount(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mount",
		Short: "Manage SSHFS mounts",
		Long: `Manage SSHFS mounts of an instance's filesystem on the host.

Add a mount with 'abox mount add', list recorded mounts with 'abox mount list',
and tear one down with 'abox mount remove' (also available as 'abox unmount').`,
		Example: `  abox mount add dev ~/mnt/dev
  abox mount list dev
  abox mount remove ~/mnt/dev`,
	}

	cmd.AddCommand(add.NewCmdAdd(f, nil))
	cmd.AddCommand(mountlist.NewCmdList(f, nil))
	cmd.AddCommand(remove.NewCmdRemove(f, nil))

	return cmd
}
