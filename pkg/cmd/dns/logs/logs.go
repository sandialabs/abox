package logs

import (
	"github.com/sandialabs/abox/internal/filtercmd"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// NewCmdLogs creates a new dns logs command.
func NewCmdLogs(f *factory.Factory) *cobra.Command {
	return filtercmd.NewDNSLogsCommand(f.IO.Out)
}
