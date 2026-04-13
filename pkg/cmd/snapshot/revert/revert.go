package revert

import (
	"context"
	"fmt"
	"os"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the revert command.
type Options struct {
	Factory      *factory.Factory
	Force        bool
	Name         string
	SnapshotName string
}

// NewCmdRevert creates a new snapshot revert command.
func NewCmdRevert(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:     "revert <instance> <name>",
		Short:   "Revert an instance to a snapshot",
		Example: `  abox snapshot revert dev before-upgrade  # Revert to a snapshot`,
		Long: `Revert an instance to a previously created snapshot.

WARNING: All changes since the snapshot was taken will be lost.

The instance must be stopped to revert to a snapshot.`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances(), completion.SnapshotsFor(0)),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.SnapshotName = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runRevert(cmd.Context(), opts, args[0], args[1])
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func runRevert(ctx context.Context, opts *Options, name, snapshotName string) error {
	_, paths, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	// Get the backend for this instance
	factory.Ensure(&opts.Factory)
	be, err := opts.Factory.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	// Check if snapshots are supported
	sm := be.Snapshot()
	if sm == nil {
		return fmt.Errorf("snapshots are not supported by the %s backend", be.Name())
	}

	// Check if VM exists
	if !be.VM().Exists(name) {
		return fmt.Errorf("VM definition for instance %q not found", name)
	}

	// Check if VM is running
	if be.VM().IsRunning(name) {
		return &cmdutil.ErrHint{
			Err:  fmt.Errorf("instance %q must be stopped to revert to a snapshot", name),
			Hint: fmt.Sprintf("Run 'abox stop %s' first", name),
		}
	}

	// Check if snapshot exists
	if !sm.Exists(name, snapshotName) {
		return fmt.Errorf("snapshot %q does not exist for instance %q", snapshotName, name)
	}

	w := opts.Factory.IO.Out
	// Confirm revert
	if !opts.Force {
		fmt.Fprintf(w, "Revert instance %q to snapshot %q?\n", name, snapshotName)
		fmt.Fprintln(w, "WARNING: All changes since this snapshot will be lost.")
		if !opts.Factory.Prompter.Confirm("Continue? [y/N] ") {
			return &cmdutil.ErrCancel{}
		}
	}

	fmt.Fprintf(w, "Reverting to snapshot %q...\n", snapshotName)

	if err := sm.Revert(ctx, name, snapshotName); err != nil {
		return fmt.Errorf("failed to revert to snapshot: %w", err)
	}

	// Clear known_hosts to avoid SSH host key mismatch after revert.
	// The VM's SSH host keys may have changed (reverted to an earlier state),
	// so we need to allow SSH to re-learn the keys on first connection.
	if err := os.Remove(paths.KnownHosts); err != nil && !os.IsNotExist(err) {
		logging.Warn("failed to clear known_hosts", "error", err)
	}

	fmt.Fprintf(w, "Instance %q reverted to snapshot %q.\n", name, snapshotName)
	fmt.Fprintf(w, "\nRun 'abox start %s' to start the instance.\n", name)

	logging.AuditInstance(name, logging.ActionSnapshotRevert, "snapshot", snapshotName)

	return nil
}
