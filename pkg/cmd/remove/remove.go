package remove

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/daemon"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/forward/shared"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

const defaultTimeout = timeout.Default

// Options holds the options for the remove command.
type Options struct {
	Factory        *factory.Factory
	Force          bool
	SkipDaemonStop bool     // Skip stopping daemons (already stopped by caller)
	Brief          bool     // Suppress final summary output
	Names          []string // Instance names to remove
}

// NewCmdRemove creates a new remove command.
func NewCmdRemove(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "remove <name...>",
		Short: "Remove one or more abox instances",
		Long: `Remove instances and all their resources.

This will:
  - Stop and delete the VM
  - Delete the network
  - Delete all instance data (disk, config, keys)`,
		Example: `  abox remove dev                          # Remove with confirmation
  abox remove dev -f                       # Skip confirmation
  abox remove dev staging                  # Remove multiple instances`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completion.Repeat(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Names = args
			if !opts.Force && len(args) > 1 {
				if !opts.Factory.IO.IsTerminal() {
					return &cmdutil.ErrHint{
						Err:  errors.New("confirmation required"),
						Hint: "Use --force to skip",
					}
				}
				w := opts.out()
				fmt.Fprintf(w, "This will permanently delete %d instances and all their data:\n", len(args))
				fmt.Fprintf(w, "  %s\n", strings.Join(args, ", "))
				if !opts.Factory.Prompter.Confirm("Are you sure? [y/N] ") {
					return &cmdutil.ErrCancel{}
				}
				opts.Force = true
			}

			if runF != nil {
				return runF(opts)
			}

			ctx := cmd.Context()
			return cmdutil.ForEach(args, func(name string) error {
				return runRemove(ctx, opts, name)
			})
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

// Run executes the remove command with the given options and instance name.
func Run(ctx context.Context, opts *Options, name string) error {
	factory.Ensure(&opts.Factory)
	return runRemove(ctx, opts, name)
}

func (o *Options) out() io.Writer { return o.Factory.IO.Out }

func runRemove(ctx context.Context, opts *Options, name string) error {
	inst, paths, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	// Get the backend for this instance
	factory.Ensure(&opts.Factory)
	w := opts.out()
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	// Confirm — In the doDown TUI path, Force is always true so this is never reached.
	if !opts.Force {
		if err := confirmRemove(opts, w, name); err != nil {
			return err
		}
	}

	fmt.Fprintf(w, "Removing instance %q...\n", name)

	stopServices(w, opts, name, paths)
	cleanupBackendResources(ctx, w, opts, be, inst, name)

	// Delete instance data (user config directory)
	fmt.Fprintln(w, "  Deleting instance data...")
	if err := config.Delete(name); err != nil {
		return fmt.Errorf("failed to delete instance data: %w", err)
	}

	deleteDiskDirectory(ctx, opts, name, paths)
	removeSocketFiles(paths)

	if !opts.Brief {
		fmt.Fprintf(w, "\nInstance %q removed.\n", name)
	}

	// Audit to syslog only - instance data already deleted
	logging.AuditInstance(name, logging.ActionInstanceRemove)

	return nil
}

// confirmRemove prompts the user for confirmation before removing an instance.
func confirmRemove(opts *Options, w io.Writer, name string) error {
	if !opts.Factory.IO.IsTerminal() {
		return &cmdutil.ErrHint{
			Err:  errors.New("confirmation required"),
			Hint: "Use --force to skip",
		}
	}
	fmt.Fprintf(w, "This will permanently delete instance %q and all its data.\n", name)
	if !opts.Factory.Prompter.Confirm("Are you sure? [y/N] ") {
		return &cmdutil.ErrCancel{}
	}
	return nil
}

// stopServices stops port forwards and daemons for the instance.
func stopServices(w io.Writer, opts *Options, name string, paths *config.Paths) {
	// Clean up port forwards
	fmt.Fprintln(w, "  Stopping port forwards...")
	if err := shared.CleanupForwards(paths.Instance); err != nil {
		logging.Warn("failed to clean up forwards", "error", err, "instance", name)
	}

	// Stop daemons if not already stopped
	if !opts.SkipDaemonStop {
		fmt.Fprintln(w, "  Stopping monitor daemon...")
		daemon.StopMonitorDaemon(name)

		fmt.Fprintln(w, "  Stopping DNS filter...")
		daemon.StopDNSFilter(name)

		fmt.Fprintln(w, "  Stopping HTTP filter...")
		daemon.StopHTTPFilter(name)
	}
}

// cleanupBackendResources removes UFW rules, the VM, nwfilter, and network.
func cleanupBackendResources(ctx context.Context, w io.Writer, opts *Options, be backend.Backend, inst *config.Instance, name string) {
	// Remove UFW rule if UFW is active
	if client, err := opts.Factory.PrivilegeClientFor(name); err == nil {
		firewall.NewUFWClient(client).Cleanup(w, inst.Bridge, "  ")
	}

	// Delete VM
	if be.VM().Exists(name) {
		fmt.Fprintln(w, "  Deleting VM...")
		if err := be.VM().Remove(ctx, name); err != nil {
			logging.Warn("failed to delete domain", "error", err, "instance", name)
		}
	}

	// Delete nwfilter
	names := be.ResourceNames(name)
	if ti := be.TrafficInterceptor(); ti != nil && ti.FilterExists(names.Filter) {
		fmt.Fprintln(w, "  Deleting network filter...")
		if err := ti.DeleteFilter(ctx, names.Filter); err != nil {
			logging.Warn("failed to delete nwfilter", "error", err, "instance", name)
		}
	}

	// Delete network
	if be.Network().Exists(inst.Bridge) {
		fmt.Fprintln(w, "  Deleting network...")
		if err := be.Network().Delete(ctx, inst.Bridge); err != nil {
			logging.Warn("failed to delete network", "error", err, "instance", name)
		}
	}
}

// deleteDiskDirectory removes the disk directory in the backend storage location via privilege helper.
func deleteDiskDirectory(ctx context.Context, opts *Options, name string, paths *config.Paths) {
	if paths.DiskDir == "" || opts.Factory == nil {
		return
	}
	client, err := opts.Factory.PrivilegeClientFor(name)
	if err == nil {
		ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
		_, err = client.RemoveAll(ctx, &rpc.PathReq{Path: paths.DiskDir})
	}
	if err != nil {
		logging.Warn("failed to delete disk directory", "error", err, "instance", name, "path", paths.DiskDir)
	}
}

// removeSocketFiles removes leftover Unix socket files.
func removeSocketFiles(paths *config.Paths) {
	if err := os.Remove(paths.DNSSocket); err != nil && !os.IsNotExist(err) {
		logging.Warn("failed to remove DNS socket", "path", paths.DNSSocket, "error", err)
	}
	if err := os.Remove(paths.HTTPSocket); err != nil && !os.IsNotExist(err) {
		logging.Warn("failed to remove HTTP socket", "path", paths.HTTPSocket, "error", err)
	}
}
