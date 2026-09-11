package stop

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/daemon"
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

	// Allow the vmnet-helper teardown (inside stopVM, on macOS ≤15) to prompt for a
	// password when attached to a terminal, so stop can kill the root-owned helper
	// without a passwordless-kill sudoers grant. No-op off macOS / on a non-TTY.
	opts.Factory.ConfigureInteractiveHelperSignaling()

	if err := stopVM(ctx, w, be, name, opts.Force); err != nil {
		return err
	}

	cleanupAfterStop(ctx, w, opts, inst, name)

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

// cleanupAfterStop tears down egress enforcement and stops the filter/monitor daemons.
func cleanupAfterStop(ctx context.Context, w io.Writer, opts *Options, inst *config.Instance, name string) {
	// Tear down egress enforcement (Linux: iptables DNS redirect + nwfilter;
	// macOS: the per-instance pf anchor) via the egress seam. Privilege is acquired
	// lazily; how much it may prompt is decided per-platform below. Any unprivileged
	// resource (e.g. the nwfilter) is removed regardless.
	if opts.Factory != nil {
		// Decide whether egress teardown may prompt for a password. The choice is
		// platform-specific (see configureStopPrivilege): Linux forces
		// non-interactive because its escalation paths (setuid helper, root,
		// external, already-running) are non-interactive, so teardown never blocks;
		// macOS gates on the TTY so that an interactive `abox stop` can flush the pf
		// anchor (its only escalation is interactive sudo) while a non-TTY run stays
		// best-effort. Leaving a stale pf anchor loaded after every stop is the leak
		// this avoids.
		configureStopPrivilege(opts.Factory)
		if be, err := opts.Factory.BackendFor(name); err == nil && be != nil {
			if ec := be.EgressController(); ec != nil {
				fmt.Fprintln(w, "Removing egress rules...")
				if err := ec.Remove(ctx, inst); err != nil {
					logging.Warn("failed to remove egress rules", "error", err, "instance", name)
				}
			}
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
}
