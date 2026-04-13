package stop

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/daemon"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the stop command.
type Options struct {
	Factory *factory.Factory
	Force   bool
	Brief   bool     // Suppress final summary output
	Names   []string // Instance names to stop
}

// NewCmdStop creates a new stop command.
func NewCmdStop(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "stop <name...>",
		Short: "Stop one or more abox instances",
		Long:  "Gracefully stop one or more running instances. Shuts down the VM and stops all filter daemons.\n\nUse --force to skip the graceful shutdown timeout.",
		Example: `  abox stop dev                            # Graceful shutdown
  abox stop dev -f                         # Force stop immediately
  abox stop dev staging                    # Stop multiple instances`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completion.Repeat(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Names = args
			if runF != nil {
				return runF(opts)
			}
			ctx := cmd.Context()
			return cmdutil.ForEach(args, func(name string) error {
				return runStop(ctx, opts, name)
			})
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Force stop (don't wait for graceful shutdown)")

	return cmd
}

// Run executes the stop command with the given options and instance name.
func Run(ctx context.Context, opts *Options, name string) error {
	factory.Ensure(&opts.Factory)
	return runStop(ctx, opts, name)
}

func (o *Options) out() io.Writer { return o.Factory.IO.Out }

func runStop(ctx context.Context, opts *Options, name string) error {
	inst, _, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	factory.Ensure(&opts.Factory)
	w := opts.out()
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	if !be.VM().IsRunning(name) {
		fmt.Fprintf(w, "Instance %q is not running.\n", name)
		return nil
	}

	if err := stopVM(ctx, w, be, name, opts.Force); err != nil {
		return err
	}

	cleanupAfterStop(w, opts, inst, name)

	if !opts.Brief {
		fmt.Fprintf(w, "\nInstance %q stopped.\n", name)
	}

	logging.AuditInstance(name, logging.ActionInstanceStop,
		"force", opts.Force,
	)

	return nil
}

// stopVM stops the VM either forcefully or gracefully with a timeout fallback.
func stopVM(ctx context.Context, w io.Writer, be backend.Backend, name string, force bool) error {
	if force {
		fmt.Fprintln(w, "Force stopping VM...")
		if err := be.VM().ForceStop(ctx, name); err != nil {
			return fmt.Errorf("failed to force stop VM: %w", err)
		}
		return nil
	}
	return gracefulStop(ctx, w, be, name)
}

// gracefulStop attempts a graceful shutdown with a 60-second timeout, then force-stops.
func gracefulStop(ctx context.Context, w io.Writer, be backend.Backend, name string) error {
	fmt.Fprint(w, "Stopping VM (graceful shutdown)")
	if err := be.VM().Stop(ctx, name); err != nil {
		return fmt.Errorf("failed to stop VM: %w", err)
	}

	for range 60 {
		select {
		case <-ctx.Done():
			fmt.Fprintln(w)
			return ctx.Err()
		case <-time.After(time.Second):
		}
		fmt.Fprint(w, ".")
		if !be.VM().IsRunning(name) {
			break
		}
	}
	fmt.Fprintln(w)

	if be.VM().IsRunning(name) {
		fmt.Fprintln(w, "Graceful shutdown timed out, forcing stop...")
		if err := be.VM().ForceStop(ctx, name); err != nil {
			return fmt.Errorf("failed to force stop VM: %w", err)
		}
	}
	return nil
}

// cleanupAfterStop removes firewall rules, stops daemons, and cleans up UFW.
func cleanupAfterStop(w io.Writer, opts *Options, inst *config.Instance, name string) {
	// Remove iptables DNS redirect rules (flush all rules for this bridge).
	// Privilege is acquired lazily (best-effort) so stop succeeds even
	// without sudo — the VM shuts down regardless and firewall rules
	// become inert.
	if opts.Factory != nil {
		if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
			fmt.Fprintln(w, "Removing DNS redirect rules...")
			firewall.NewIPTablesClient(client).Flush(inst.Bridge)
		}
	}

	if inst.Monitor.Enabled {
		fmt.Fprintln(w, "Stopping monitor daemon...")
		daemon.StopMonitorDaemon(name)
	}

	fmt.Fprintln(w, "Stopping HTTP filter...")
	daemon.StopHTTPFilter(name)

	fmt.Fprintln(w, "Stopping DNS filter...")
	daemon.StopDNSFilter(name)

	if opts.Factory != nil {
		if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
			firewall.NewUFWClient(client).Cleanup(w, inst.Bridge, "")
		}
	}
}
