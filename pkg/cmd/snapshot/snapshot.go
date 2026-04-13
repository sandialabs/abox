package snapshot

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/snapshot/create"
	snapshotlist "github.com/sandialabs/abox/pkg/cmd/snapshot/list"
	"github.com/sandialabs/abox/pkg/cmd/snapshot/remove"
	"github.com/sandialabs/abox/pkg/cmd/snapshot/revert"

	"github.com/spf13/cobra"
)

// NewCmdSnapshot creates a new snapshot command.
func NewCmdSnapshot(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Manage instance snapshots",
		Long:  `Create, list, remove, and revert instance snapshots.`,
	}

	cmd.AddCommand(create.NewCmdCreate(f, nil))
	cmd.AddCommand(snapshotlist.NewCmdList(f, nil))
	cmd.AddCommand(remove.NewCmdRemove(f, nil))
	cmd.AddCommand(revert.NewCmdRevert(f, nil))

	return cmd
}
