package list

import (
	"fmt"
	"os"

	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// allowlistJSON is the JSON representation of the allowlist.
type allowlistJSON struct {
	Domains []string `json:"domains"`
	Count   int      `json:"count"`
}

// Options holds the options for the list command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdList creates a new allowlist list command.
func NewCmdList(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "list <instance>",
		Aliases: []string{"ls"},
		Short:   "List all domains in the allowlist",
		Long: `List all domains in the allowlist for a running instance.

Queries the DNS and HTTP filter daemons and displays the combined set of
allowed domains. Use --json or --jq for machine-readable output.`,
		Example: `  abox allowlist list dev                  # Show all allowed domains
  abox allowlist ls dev                    # Short alias
  abox allowlist list dev --json           # JSON output
  abox allowlist list dev --jq '.domains'  # Extract domain list`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runList(f, opts.Exporter, args[0])
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runList(f *factory.Factory, exporter *cmdutil.Exporter, name string) error {
	_, paths, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	client, allowlistErr := f.AllowlistClient(name)
	if allowlistErr != nil {
		// Fall back to reading file directly if DNS filter not running
		content, readErr := os.ReadFile(paths.Allowlist)
		if readErr != nil {
			return fmt.Errorf("failed to read allowlist: %w", readErr)
		}
		fmt.Fprint(f.IO.Out, string(content))
		return nil
	}

	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	resp, err := client.List(ctx, &rpc.Empty{})
	if err != nil {
		return fmt.Errorf("failed to list domains: %w", err)
	}

	out := f.IO.Out

	if exporter.Enabled() {
		return exporter.Write(out, allowlistJSON{
			Domains: resp.Domains,
			Count:   len(resp.Domains),
		})
	}

	if len(resp.Domains) == 0 {
		return &cmdutil.NoResultsError{Message: "no allowed domains"}
	}

	f.IO.StartPager()
	defer f.IO.StopPager()

	if f.IO.IsTerminal() {
		fmt.Fprintln(out, "Allowed domains:")
		for _, d := range resp.Domains {
			fmt.Fprintf(out, "  %s\n", d)
		}
		fmt.Fprintf(out, "\nTotal: %d domains\n", len(resp.Domains))
	} else {
		for _, d := range resp.Domains {
			fmt.Fprintln(out, d)
		}
	}

	return nil
}
