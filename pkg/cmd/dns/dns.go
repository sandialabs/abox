package dns

import (
	"github.com/sandialabs/abox/pkg/cmd/dns/level"
	"github.com/sandialabs/abox/pkg/cmd/dns/logs"
	"github.com/sandialabs/abox/pkg/cmd/dns/serve"
	dnsstatus "github.com/sandialabs/abox/pkg/cmd/dns/status"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// NewCmdDNS creates a new dns command.
func NewCmdDNS(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Manage DNS filter",
		Long:  `Manage the DNS filter for an instance.`,
	}

	cmd.AddCommand(level.NewCmdLevel(f))
	cmd.AddCommand(logs.NewCmdLogs(f))
	cmd.AddCommand(dnsstatus.NewCmdStatus(f, nil))
	cmd.AddCommand(serve.NewCmdServe(f, nil))

	return cmd
}
