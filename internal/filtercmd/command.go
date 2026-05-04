// Package filtercmd provides shared command construction for filter log viewing.
package filtercmd

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/sandialabs/abox/pkg/cmd/completion"
)

// logsCmdUse is the cobra Use string shared by all filter logs subcommands.
const logsCmdUse = "logs <instance>"

// LogsConfig holds configuration for creating a logs command.
type LogsConfig struct {
	// Use is the command use string (e.g., "logs <instance>")
	Use string
	// Short is the short description
	Short string
	// Long is the long description
	Long string
	// Example is the example usage (optional)
	Example string
	// FilterType identifies which filter's logs to view
	FilterType FilterType
	// HasServiceFlag indicates whether to include the --service flag
	HasServiceFlag bool
	// ValidArgsFunc is the completion function for arguments
	ValidArgsFunc func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)
}

// NewLogsCommand creates a new logs command with the given configuration.
// This reduces duplication across dns logs, http logs, monitor logs, and audit logs commands.
func NewLogsCommand(w io.Writer, cfg LogsConfig) *cobra.Command {
	opts := &LogOptions{Out: w}

	cmd := &cobra.Command{
		Use:               cfg.Use,
		Short:             cfg.Short,
		Long:              cfg.Long,
		Example:           cfg.Example,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cfg.ValidArgsFunc,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ViewLogs(*opts, args[0], cfg.FilterType)
		},
	}

	cmd.Flags().BoolVarP(&opts.Follow, "follow", "f", false, "Follow log output")
	cmd.Flags().IntVarP(&opts.Lines, "lines", "n", 50, "Number of lines to show")

	if cfg.HasServiceFlag {
		cmd.Flags().BoolVar(&opts.Service, "service", false, "Show service logs instead of traffic logs")
	}

	cmd.Flags().StringVar(&opts.JQ, "jq", "", "Filter JSON output with a jq expression")

	return cmd
}

// NewDNSLogsCommand creates the standard DNS logs command.
func NewDNSLogsCommand(w io.Writer) *cobra.Command {
	return NewLogsCommand(w, LogsConfig{
		Use:   logsCmdUse,
		Short: "View DNS filter logs",
		Long: `View the DNS filter logs for an instance.

By default, shows traffic logs (allow/block decisions in JSON format).
Use --service to view daemon stderr logs instead.
Use -f/--follow to stream new log entries.
Use --jq to filter JSON traffic logs with a jq expression.`,
		Example: `  # Show last 50 entries
  abox dns logs dev

  # Extract just the domain field
  abox dns logs dev --jq '.domain'

  # Show only blocked queries
  abox dns logs dev --jq 'select(.action == "block")'

  # Follow and filter live
  abox dns logs dev -f --jq '.domain'`,
		FilterType:     FilterDNS,
		HasServiceFlag: true,
		ValidArgsFunc:  completion.Sequence(completion.AllInstances()),
	})
}

// NewHTTPLogsCommand creates the standard HTTP logs command.
func NewHTTPLogsCommand(w io.Writer) *cobra.Command {
	return NewLogsCommand(w, LogsConfig{
		Use:   logsCmdUse,
		Short: "View HTTP filter logs",
		Long: `View the HTTP filter logs for an instance.

By default, shows traffic logs (allow/block decisions in JSON format).
Use --service to view daemon stderr logs instead.
Use -f/--follow to stream new log entries.
Use --jq to filter JSON traffic logs with a jq expression.`,
		Example: `  # Show last 50 entries
  abox http logs dev

  # Show only blocked requests
  abox http logs dev --jq 'select(.action == "block")'

  # Follow and filter live
  abox http logs dev -f --jq 'select(.action == "block")'`,
		FilterType:     FilterHTTP,
		HasServiceFlag: true,
		ValidArgsFunc:  completion.Sequence(completion.AllInstances()),
	})
}

// NewMonitorLogsCommand creates the standard monitor logs command.
func NewMonitorLogsCommand(w io.Writer) *cobra.Command {
	return NewLogsCommand(w, LogsConfig{
		Use:   logsCmdUse,
		Short: "View monitor logs",
		Long: `View Tetragon monitoring events from the VM.

Events are logged by the monitor daemon which reads from virtio-serial.

Events show:
  - Process executions (EXEC)
  - File operations (FILE)
  - Network connections (NET)

The monitor uses a secure virtio-serial channel that:
  - Works independently of VM network (tamper-resistant)
  - Is invisible to processes inside the VM
  - Bypasses the guest network stack entirely

Prerequisites:
  - Instance must have monitoring enabled (monitor: enabled: true in abox.yaml)
  - Instance must be running

Use --jq to filter JSON event logs with a jq expression.

Tip: Pipe to jq for pretty JSON: abox monitor logs dev | jq .`,
		Example: `  # Show last 50 events
  abox monitor logs dev

  # Follow live events
  abox monitor logs dev -f

  # Show last 100 events
  abox monitor logs dev -n 100

  # Show only EXEC events
  abox monitor logs dev --jq 'select(.event == "EXEC")'

  # Pretty-print JSON with jq
  abox monitor logs dev | jq .`,
		FilterType:     FilterMonitor,
		HasServiceFlag: true,
		ValidArgsFunc:  completion.Sequence(completion.RunningInstances()),
	})
}
