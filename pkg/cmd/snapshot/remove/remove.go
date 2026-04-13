package remove

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the remove command.
type Options struct {
	Factory      *factory.Factory
	Force        bool
	Name         string
	SnapshotName string
}

// NewCmdRemove creates a new snapshot remove command.
func NewCmdRemove(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:     "remove <instance> <name>",
		Aliases: []string{"rm"},
		Short:   "Remove a snapshot",
		Long:    `Remove a snapshot from an instance.`,
		Example: `  abox snapshot remove dev before-upgrade     # Remove with confirmation
  abox snapshot rm dev before-upgrade -f      # Skip confirmation`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances(), completion.SnapshotsFor(0)),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.SnapshotName = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runRemove(cmd.Context(), opts, args[0], args[1])
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func runRemove(ctx context.Context, opts *Options, name, snapshotName string) error {
	_, _, err := instance.LoadRequired(name)
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

	// Check if snapshot exists
	if !sm.Exists(name, snapshotName) {
		return fmt.Errorf("snapshot %q does not exist for instance %q", snapshotName, name)
	}

	out := opts.Factory.IO.Out

	// Confirm removal
	if !opts.Force {
		if !opts.Factory.Prompter.Confirm(fmt.Sprintf("Remove snapshot %q from instance %q? [y/N] ", snapshotName, name)) {
			return &cmdutil.ErrCancel{}
		}
	}

	fmt.Fprintf(out, "Removing snapshot %q...\n", snapshotName)

	if err := sm.Delete(ctx, name, snapshotName); err != nil {
		return fmt.Errorf("failed to remove snapshot: %w", err)
	}

	fmt.Fprintf(out, "Snapshot %q removed.\n", snapshotName)

	logging.AuditInstance(name, logging.ActionSnapshotRemove, "snapshot", snapshotName)

	return nil
}
