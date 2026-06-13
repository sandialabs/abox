// Package remote implements the "abox remote" command group for managing git
// remotes that connect to abox instances.
package remote

import (
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/remote/add"

	"github.com/spf13/cobra"
)

// NewCmdRemote creates a new remote command.
func NewCmdRemote(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage git remotes that connect to instances",
		Long: `Manage git remotes, in the current repository, that connect to git
repositories inside abox instances.

Remotes route through 'abox ssh', reusing the instance's scoped SSH key, its
per-instance known_hosts, and its current IP address — so nothing is written to
your host SSH configuration and the remote survives instance restarts.`,
	}

	cmd.AddCommand(add.NewCmdAdd(f, nil))

	return cmd
}
