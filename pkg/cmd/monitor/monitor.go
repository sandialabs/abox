// Package monitor provides the abox monitor command for managing Tetragon monitoring.
package monitor

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/monitor/logs"
	"github.com/sandialabs/abox/pkg/cmd/monitor/serve"
	"github.com/sandialabs/abox/pkg/cmd/monitor/status"
)

// NewCmdMonitor creates a new monitor command.
func NewCmdMonitor(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Manage Tetragon monitoring",
		Long:  `Manage Tetragon agent activity monitoring for an instance.`,
	}

	cmd.AddCommand(logs.NewCmdLogs(f))
	cmd.AddCommand(serve.NewCmdServe(f, nil))
	cmd.AddCommand(status.NewCmdStatus(f, nil))

	return cmd
}
