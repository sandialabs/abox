package add

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

// Options holds the options for the add command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Domain  string
}

// NewCmdAdd creates a new allowlist add command.
func NewCmdAdd(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "add <instance> <domain>",
		Short: "Add a domain to the allowlist",
		Long:  "Add a domain to the instance allowlist. Subdomains are automatically included.\n\nChanges take effect immediately on both DNS and HTTP filters.",
		Example: `  abox allowlist add dev github.com        # Allow a domain and its subdomains
  abox allowlist add dev '*.example.com'   # Wildcard pattern`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Domain = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runAdd(f, args[0], args[1])
		},
	}

	return cmd
}

func runAdd(f *factory.Factory, name, domain string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	if err := validation.ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}

	return f.WithAllowlistClient(name, func(ctx context.Context, client rpc.AllowlistClient) error {
		resp, err := client.Add(ctx, &rpc.DomainReq{Domain: domain})
		if err != nil {
			return fmt.Errorf("failed to add domain: %w", err)
		}

		fmt.Fprintln(f.IO.Out, resp.Message)

		logging.AuditInstance(name, logging.ActionAllowlistAdd,
			"domain", domain,
		)

		return nil
	})
}
