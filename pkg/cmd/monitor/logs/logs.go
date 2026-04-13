// Package logs provides the abox monitor logs command for viewing Tetragon events.
package logs

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/internal/filtercmd"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// NewCmdLogs creates a new monitor logs command.
func NewCmdLogs(f *factory.Factory) *cobra.Command {
	return filtercmd.NewMonitorLogsCommand(f.IO.Out)
}
