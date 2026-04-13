// Package logs provides the abox logs command group.
package logs

import (
	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// NewCmdLogs creates a new logs command.
func NewCmdLogs(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "View instance logs",
		Long: `View various logs for an instance.

For filter-specific logs, use:
  abox dns logs <instance>       DNS traffic logs
  abox http logs <instance>      HTTP traffic logs
  abox monitor logs <instance>   Tetragon events

For audit logs, use journalctl:
  journalctl -t abox             All abox audit events
  journalctl -t abox --since "1 hour ago"`,
	}

	return cmd
}
