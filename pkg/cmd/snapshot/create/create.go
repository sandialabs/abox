package create

import (
	"context"
	"fmt"
	"time"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the snapshot create command.
type Options struct {
	Factory      *factory.Factory
	Name         string
	SnapshotName string
}

// NewCmdCreate creates a new snapshot create command.
func NewCmdCreate(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "create <instance> [name]",
		Short: "Create a snapshot of an instance",
		Example: `  abox snapshot create dev                 # Auto-generated snapshot name
  abox snapshot create dev before-upgrade  # Named snapshot`,
		Long: `Create a snapshot of an instance.

If no name is provided, an auto-generated name will be used in the format:
snap-YYYYMMDD-HHMMSS

The instance must be stopped to create a snapshot.`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if len(args) > 1 {
				opts.SnapshotName = args[1]
			}
			if runF != nil {
				return runF(opts)
			}
			return runCreate(cmd.Context(), f, opts.Name, opts.SnapshotName)
		},
	}

	return cmd
}

func runCreate(ctx context.Context, f *factory.Factory, name, snapshotName string) error {
	_, _, err := instance.LoadRequired(name)
	if err != nil {
		return err
	}

	// Get the backend for this instance
	if f == nil {
		f = factory.New()
	}
	be, err := f.BackendFor(name)
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
			Err:  fmt.Errorf("instance %q must be stopped to create a snapshot", name),
			Hint: fmt.Sprintf("Run 'abox stop %s' first", name),
		}
	}

	// Generate snapshot name if not provided
	if snapshotName == "" {
		snapshotName = "snap-" + time.Now().Format("20060102-150405")
	}

	// Validate snapshot name
	if err := validation.ValidateSnapshotName(snapshotName); err != nil {
		return err
	}

	// Check if snapshot already exists
	if sm.Exists(name, snapshotName) {
		return fmt.Errorf("snapshot %q already exists for instance %q", snapshotName, name)
	}

	fmt.Fprintf(f.IO.Out, "Creating snapshot %q for instance %q...\n", snapshotName, name)

	if err := sm.Create(ctx, name, snapshotName, ""); err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	fmt.Fprintf(f.IO.Out, "Snapshot %q created successfully.\n", snapshotName)

	logging.AuditInstance(name, logging.ActionSnapshotCreate, "snapshot", snapshotName)

	return nil
}
