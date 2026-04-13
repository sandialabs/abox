// Package level provides the dns level command for managing log levels.
package level

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// NewCmdLevel creates a new dns level command.
func NewCmdLevel(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "level <instance> [debug|info|warn|error]",
		Short: "Get or set DNS filter log level",
		Example: `  abox dns level dev                       # Show current log level
  abox dns level dev debug                 # Set log level to debug`,
		Long: `Get or set the log level for the DNS filter.

Without a level argument, displays the current log level.
With a level argument, sets the log level to the specified value.

Valid levels: debug, info, warn, error`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances(), completion.Values(logging.ValidLevels...)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				return runGetLevel(f, args[0])
			}
			return runSetLevel(f, args[0], args[1])
		},
	}

	return cmd
}

func runGetLevel(f *factory.Factory, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	client, err := f.DNSClient(name)
	if err != nil {
		return err
	}

	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	resp, err := client.GetLogLevel(ctx, &rpc.Empty{})
	if err != nil {
		return fmt.Errorf("failed to get log level: %w", err)
	}

	fmt.Fprintln(f.IO.Out, resp.Level)
	return nil
}

func runSetLevel(f *factory.Factory, name, level string) error {
	if !logging.IsValidLevel(level) {
		return fmt.Errorf("invalid log level %q: must be one of debug, info, warn, error", level)
	}

	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	client, err := f.DNSClient(name)
	if err != nil {
		return err
	}

	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	resp, err := client.SetLogLevel(ctx, &rpc.LogLevelReq{Level: level})
	if err != nil {
		return fmt.Errorf("failed to set log level: %w", err)
	}

	fmt.Fprintln(f.IO.Out, resp.Message)
	return nil
}
