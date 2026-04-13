package profile

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// validSubcommands are the allowed profile subcommands.
var validSubcommands = map[string]bool{
	"show":   true,
	"export": true,
	"clear":  true,
	"count":  true,
}

// Options holds the options for the profile command.
type Options struct {
	Factory    *factory.Factory
	Force      bool
	Name       string
	Subcommand string
}

// NewCmdProfile creates a new net profile command.
func NewCmdProfile(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "profile <instance> [show|export|clear|count]",
		Short: "View captured domains from passive mode",
		Long: `View captured domains from passive mode.

When filters are in passive mode, domains are captured for profiling.
This command shows those captured domains from both DNS and HTTP filters.

Actions: show (default), export, clear, count.

Usage flow:
  1. abox net filter <instance> passive  # Enter passive mode
  2. (Run your application in the VM)
  3. abox net profile <instance> export  # Get the allowlist
  4. abox net filter <instance> active   # Return to blocking mode`,
		Example: `  abox net profile dev                  # Show captured domains
  abox net profile dev export           # Export as allowlist format
  abox net profile dev clear            # Clear captured domains
  abox net profile dev count            # Show capture counts`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Subcommand = "show" // default
			if len(args) > 1 {
				opts.Subcommand = args[1]
			}
			if runF != nil {
				return runF(opts)
			}
			return runProfile(opts, args[0], opts.Subcommand)
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Skip confirmation prompt for clear")

	return cmd
}

func runProfile(opts *Options, name, subcommand string) error {
	if _, _, err := instance.LoadRequired(name); err != nil {
		return err
	}

	if !validSubcommands[subcommand] {
		return fmt.Errorf("invalid subcommand %q: must be one of show, export, clear, count", subcommand)
	}

	// Ensure factory is initialized
	factory.Ensure(&opts.Factory)

	switch subcommand {
	case "show":
		return runShow(opts.Factory, name)
	case "export":
		return runExport(opts.Factory, name)
	case "clear":
		return runClear(opts, name)
	case "count":
		return runCount(opts.Factory, name)
	default:
		return fmt.Errorf("unknown subcommand: %s", subcommand)
	}
}

func runShow(f *factory.Factory, name string) error {
	var dnsDomains, httpDomains []string
	var dnsErr, httpErr error

	dnsErr = f.WithDNSClient(name, func(ctx context.Context, client rpc.DNSFilterClient) error {
		resp, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "show"})
		if err != nil {
			return err
		}
		dnsDomains = resp.Domains
		return nil
	})

	httpErr = f.WithHTTPClient(name, func(ctx context.Context, client rpc.HTTPFilterClient) error {
		resp, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "show"})
		if err != nil {
			return err
		}
		httpDomains = resp.Domains
		return nil
	})

	out := f.IO.Out
	fmt.Fprintln(out, "[DNS Filter]")
	switch {
	case dnsErr != nil:
		logging.Warn("failed to get DNS profile", "error", dnsErr, "instance", name)
	case len(dnsDomains) == 0:
		fmt.Fprintln(out, "  No domains captured")
	default:
		for _, d := range dnsDomains {
			fmt.Fprintf(out, "  %s\n", d)
		}
	}

	fmt.Fprintln(out, "\n[HTTP Filter]")
	switch {
	case httpErr != nil:
		logging.Warn("failed to get HTTP profile", "error", httpErr, "instance", name)
	case len(httpDomains) == 0:
		fmt.Fprintln(out, "  No domains captured")
	default:
		for _, d := range httpDomains {
			fmt.Fprintf(out, "  %s\n", d)
		}
	}

	if dnsErr != nil && httpErr != nil {
		return errors.New("failed to get profile from both filters")
	}

	return nil
}

func runExport(f *factory.Factory, name string) error {
	var dnsDomains, httpDomains []string
	var dnsErr, httpErr error

	dnsErr = f.WithDNSClient(name, func(ctx context.Context, client rpc.DNSFilterClient) error {
		resp, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "show"})
		if err != nil {
			return err
		}
		dnsDomains = resp.Domains
		return nil
	})

	httpErr = f.WithHTTPClient(name, func(ctx context.Context, client rpc.HTTPFilterClient) error {
		resp, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "show"})
		if err != nil {
			return err
		}
		httpDomains = resp.Domains
		return nil
	})

	if dnsErr != nil && httpErr != nil {
		return fmt.Errorf("failed to get profile from both filters: DNS: %w, HTTP: %w", dnsErr, httpErr)
	}

	// Merge and deduplicate domains
	domainSet := make(map[string]bool)
	for _, d := range dnsDomains {
		domainSet[d] = true
	}
	for _, d := range httpDomains {
		domainSet[d] = true
	}

	// Sort alphabetically
	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	// Output in allowlist format
	out := f.IO.Out
	fmt.Fprintln(out, "# Captured domains from DNS and HTTP filters")
	fmt.Fprintln(out, "# Add these to your allowlist with: abox allowlist add <instance> <domain>")
	for _, d := range domains {
		fmt.Fprintln(out, d)
	}

	return nil
}

func runClear(opts *Options, name string) error {
	out := opts.Factory.IO.Out

	// Confirm unless --force is set
	if !opts.Force {
		if !opts.Factory.Prompter.Confirm(fmt.Sprintf("Clear all captured domains from instance %q? [y/N] ", name)) {
			return &cmdutil.ErrCancel{}
		}
	}

	var dnsErr, httpErr error

	dnsErr = opts.Factory.WithDNSClient(name, func(ctx context.Context, client rpc.DNSFilterClient) error {
		_, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "clear"})
		return err
	})

	httpErr = opts.Factory.WithHTTPClient(name, func(ctx context.Context, client rpc.HTTPFilterClient) error {
		_, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "clear"})
		return err
	})

	fmt.Fprintln(out, "[DNS Filter]")
	if dnsErr != nil {
		logging.Warn("failed to clear DNS profile", "error", dnsErr, "instance", name)
	} else {
		fmt.Fprintln(out, "  Profile cleared")
	}

	fmt.Fprintln(out, "\n[HTTP Filter]")
	if httpErr != nil {
		logging.Warn("failed to clear HTTP profile", "error", httpErr, "instance", name)
	} else {
		fmt.Fprintln(out, "  Profile cleared")
	}

	if dnsErr != nil && httpErr != nil {
		return errors.New("failed to clear profile on both filters")
	}

	logging.AuditInstance(name, logging.ActionProfileClear)

	return nil
}

func runCount(f *factory.Factory, name string) error {
	var dnsCount, httpCount int32
	var dnsErr, httpErr error

	dnsErr = f.WithDNSClient(name, func(ctx context.Context, client rpc.DNSFilterClient) error {
		resp, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "count"})
		if err != nil {
			return err
		}
		dnsCount = resp.Count
		return nil
	})

	httpErr = f.WithHTTPClient(name, func(ctx context.Context, client rpc.HTTPFilterClient) error {
		resp, err := client.Profile(ctx, &rpc.ProfileReq{Subcommand: "count"})
		if err != nil {
			return err
		}
		httpCount = resp.Count
		return nil
	})

	out := f.IO.Out
	fmt.Fprintln(out, "[DNS Filter]")
	if dnsErr != nil {
		logging.Warn("failed to count DNS profile", "error", dnsErr, "instance", name)
	} else {
		fmt.Fprintf(out, "  %d domains captured\n", dnsCount)
	}

	fmt.Fprintln(out, "\n[HTTP Filter]")
	if httpErr != nil {
		logging.Warn("failed to count HTTP profile", "error", httpErr, "instance", name)
	} else {
		fmt.Fprintf(out, "  %d domains captured\n", httpCount)
	}

	if dnsErr != nil && httpErr != nil {
		return errors.New("failed to get count from both filters")
	}

	return nil
}
