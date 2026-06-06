package filter

import (
	"context"
	"errors"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the net filter command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Mode    string
}

// NewCmdFilter creates a new net filter command.
func NewCmdFilter(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "filter <instance> [active|passive]",
		Short: "Get or set filtering mode for both DNS and HTTP filters",
		Long: `Get or set filtering mode for both DNS and HTTP filters at once.

Modes:
  active   Block queries/requests not in the allowlist (default)
  passive  Allow all queries/requests and capture domains for profile

Passive mode is useful for discovering which domains an application needs.
Use 'abox net profile <instance> export' to get the captured domains.`,
		Example: `  abox net filter dev                      # Show current filter mode
  abox net filter dev active               # Block domains not in allowlist
  abox net filter dev passive              # Allow all, capture for profiling`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances(), completion.Values(modeActive, modePassive)),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if len(args) > 1 {
				opts.Mode = args[1]
			}
			if runF != nil {
				return runF(opts)
			}
			return runFilter(f, args[0], opts.Mode)
		},
	}

	return cmd
}

// Filter mode names (CLI argument values).
const (
	modeActive  = "active"
	modePassive = "passive"
)

// validModes are the allowed filter modes
var validModes = map[string]bool{
	modeActive:  true,
	modePassive: true,
}

func runFilter(f *factory.Factory, name, mode string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	if mode != "" && !validModes[mode] {
		return fmt.Errorf("invalid mode %q: must be active or passive", mode)
	}

	var dnsResp, httpResp *rpc.StringMsg
	var dnsErr, httpErr error

	// Set DNS filter mode
	dnsErr = f.WithDNSClient(name, func(ctx context.Context, client rpc.DNSFilterClient) error {
		var err error
		dnsResp, err = client.SetMode(ctx, &rpc.ModeReq{Mode: mode})
		return err
	})

	// Set HTTP filter mode
	httpErr = f.WithHTTPClient(name, func(ctx context.Context, client rpc.HTTPFilterClient) error {
		var err error
		httpResp, err = client.SetMode(ctx, &rpc.ModeReq{Mode: mode})
		return err
	})

	// Report results
	out := f.IO.Out
	fmt.Fprintln(out, "[DNS Filter]")
	if dnsErr != nil {
		logging.Warn("failed to set DNS filter mode", "error", dnsErr, "instance", name)
	} else if dnsResp != nil {
		fmt.Fprintf(out, "  %s\n", dnsResp.Message)
	}

	fmt.Fprintln(out, "\n[HTTP Filter]")
	if httpErr != nil {
		logging.Warn("failed to set HTTP filter mode", "error", httpErr, "instance", name)
	} else if httpResp != nil {
		fmt.Fprintf(out, "  %s\n", httpResp.Message)
	}

	if mode == modePassive {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Passive mode: All requests allowed and captured for profiling.")
		fmt.Fprintln(out, "Use 'abox net profile "+name+" export' to view captured domains.")
	}

	// Only log if we actually changed the mode
	if mode != "" {
		action := logging.ActionModeActive
		if mode == modePassive {
			action = logging.ActionModePassive
		}
		logging.AuditInstance(name, action)
	}

	// Return error if both failed
	if dnsErr != nil && httpErr != nil {
		return errors.New("failed to set mode on both filters")
	}

	return nil
}
