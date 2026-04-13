package allowlist

import (
	"github.com/sandialabs/abox/pkg/cmd/allowlist/add"
	"github.com/sandialabs/abox/pkg/cmd/allowlist/edit"
	allowlistlist "github.com/sandialabs/abox/pkg/cmd/allowlist/list"
	"github.com/sandialabs/abox/pkg/cmd/allowlist/reload"
	"github.com/sandialabs/abox/pkg/cmd/allowlist/remove"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// NewCmdAllowlist creates a new allowlist command.
func NewCmdAllowlist(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allowlist",
		Short: "Manage domain allowlist",
		Long: `Manage the domain allowlist for an instance.

The allowlist is shared by both DNS and HTTP filters.`,
	}

	cmd.AddCommand(add.NewCmdAdd(f, nil))
	cmd.AddCommand(remove.NewCmdRemove(f, nil))
	cmd.AddCommand(allowlistlist.NewCmdList(f, nil))
	cmd.AddCommand(edit.NewCmdEdit(f, nil))
	cmd.AddCommand(reload.NewCmdReload(f, nil))

	return cmd
}
