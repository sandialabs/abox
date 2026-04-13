package status

import (
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the http status command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdStatus creates a new http status command.
func NewCmdStatus(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "status <instance>",
		Short: "Show HTTP filter status",
		Example: `  abox http status dev                     # Show HTTP filter status
  abox http status dev --json              # JSON output
  abox http status dev --jq '.mode'        # Extract filter mode`,
		Long: `Show the current status of the HTTP filter for an instance.

Displays the filter mode, port, number of allowed domains, request statistics,
and uptime.`,
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

	client, err := f.HTTPClient(name)
	if err != nil {
		if exporter.Enabled() {
			return exporter.Write(f.IO.Out, filterbase.StatusJSON{
				Filter:  "HTTP",
				Running: false,
			})
		}
		fmt.Fprintln(f.IO.Out, "HTTP filter: not running")
		return nil
	}

	ctx, cancel := httpfilter.ClientContext()
	defer cancel()

	status, err := client.Status(ctx, &rpc.Empty{})
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	data := filterbase.StatusData{
		FilterName: "HTTP",
		Mode:       status.Mode,
		Port:       status.HttpPort,
		Domains:    status.Domains,
		Total:      status.TotalRequests,
		Allowed:    status.AllowedRequests,
		Blocked:    status.BlockedRequests,
		Uptime:     status.Uptime,
		MITM:       status.MitmEnabled,
	}

	if exporter.Enabled() {
		return exporter.Write(f.IO.Out, data.ToJSON())
	}

	filterbase.DisplayStatus(f.IO.Out, data)
	return nil
}
