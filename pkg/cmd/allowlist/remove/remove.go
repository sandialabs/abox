package remove

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the remove command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Domain  string
}

// NewCmdRemove creates a new allowlist remove command.
func NewCmdRemove(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "remove <instance> <domain>",
		Aliases: []string{"rm"},
		Short:   "Remove a domain from the allowlist",
		Long: `Remove a domain from the allowlist for a running instance.

The domain must match exactly as it appears in the allowlist. Wildcard
entries (e.g., *.example.com) must be removed using the same wildcard form.`,
		Example: `  abox allowlist remove dev github.com     # Remove a domain
  abox allowlist rm dev github.com         # Short alias`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Domain = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runRemove(f, args[0], args[1])
		},
	}

	return cmd
}

func runRemove(f *factory.Factory, name, domain string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	if err := validation.ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}

	return f.WithAllowlistClient(name, func(ctx context.Context, client rpc.AllowlistClient) error {
		resp, err := client.Remove(ctx, &rpc.DomainReq{Domain: domain})
		if err != nil {
			return fmt.Errorf("failed to remove domain: %w", err)
		}

		fmt.Fprintln(f.IO.Out, resp.Message)

		logging.AuditInstance(name, logging.ActionAllowlistRemove,
			"domain", domain,
		)

		return nil
	})
}
