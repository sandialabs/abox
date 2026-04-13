package reload

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the reload command.
type Options struct {
	Factory *factory.Factory
	Name    string
}

// NewCmdReload creates a new allowlist reload command.
func NewCmdReload(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "reload <instance>",
		Short: "Reload the allowlist from file",
		Long: `Reload the allowlist from the instance's allowlist file on disk.

This re-reads the allowlist file and updates both the DNS and HTTP filter
daemons. Use this after manually editing the allowlist file, or after
running 'abox allowlist add' or 'abox allowlist remove'.`,
		Example:           `  abox allowlist reload dev                # Reload allowlist from disk`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runReload(f, args[0])
		},
	}

	return cmd
}

func runReload(f *factory.Factory, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	var dnsErr, httpErr error

	dnsErr = f.WithAllowlistClient(name, func(ctx context.Context, client rpc.AllowlistClient) error {
		resp, err := client.Reload(ctx, &rpc.Empty{})
		if err != nil {
			return err
		}
		fmt.Fprintf(f.IO.Out, "DNS: %s\n", resp.Message)
		return nil
	})

	httpErr = f.WithHTTPAllowlistClient(name, func(ctx context.Context, client rpc.AllowlistClient) error {
		resp, err := client.Reload(ctx, &rpc.Empty{})
		if err != nil {
			return err
		}
		fmt.Fprintf(f.IO.Out, "HTTP: %s\n", resp.Message)
		return nil
	})

	if dnsErr != nil && httpErr != nil {
		return fmt.Errorf("no filters running for instance %q", name)
	}

	logging.AuditInstance(name, logging.ActionAllowlistReload)

	return nil
}
