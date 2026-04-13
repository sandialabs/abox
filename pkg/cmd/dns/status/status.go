package status

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the dns status command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdStatus creates a new dns status command.
func NewCmdStatus(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "status <instance>",
		Short: "Show DNS filter status",
		Example: `  abox dns status dev                      # Show DNS filter status
  abox dns status dev --json               # JSON output
  abox dns status dev --jq '.mode'         # Extract filter mode`,
		Long: `Show the current status of the DNS filter for an instance.

Displays the filter mode, number of allowed domains, query statistics,
cache hits, and uptime.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runStatus(f, opts.Exporter, args[0])
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runStatus(f *factory.Factory, exporter *cmdutil.Exporter, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	client, err := f.DNSClient(name)
	if err != nil {
		if exporter.Enabled() {
			return exporter.Write(f.IO.Out, filterbase.StatusJSON{
				Filter:  "DNS",
				Running: false,
			})
		}
		fmt.Fprintln(f.IO.Out, "DNS filter: not running")
		return nil
	}

	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	resp, err := client.Status(ctx, &rpc.Empty{})
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	data := filterbase.StatusData{
		FilterName: "DNS",
		Mode:       resp.Mode,
		Port:       resp.DnsPort,
		Domains:    resp.Domains,
		Total:      resp.TotalQueries,
		Allowed:    resp.AllowedQueries,
		Blocked:    resp.BlockedQueries,
		Uptime:     resp.Uptime,
	}

	if exporter.Enabled() {
		return exporter.Write(f.IO.Out, data.ToJSON())
	}

	filterbase.DisplayStatus(f.IO.Out, data)
	return nil
}
