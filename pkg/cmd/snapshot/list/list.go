package list

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/tableprinter"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// snapshotJSON is the JSON representation of a snapshot.
type snapshotJSON struct {
	Name         string `json:"name"`
	CreationTime string `json:"created"`
	State        string `json:"state"`
	Current      bool   `json:"current"`
}

// Options holds the options for the snapshot list command.
type Options struct {
	Factory  *factory.Factory
	Exporter *cmdutil.Exporter
	Name     string
}

// NewCmdList creates a new snapshot list command.
func NewCmdList(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "list <instance>",
		Aliases: []string{"ls"},
		Short:   "List snapshots of an instance",
		Long:    `List all snapshots for an instance.`,
		Example: `  abox snapshot list dev                   # List all snapshots
  abox snapshot ls dev                     # Short alias
  abox snapshot list dev --json            # JSON output
  abox snapshot list dev --jq '.[].name'   # List snapshot names only`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runList(cmd.Context(), f, opts.Exporter, args[0])
		},
	}

	opts.Exporter = cmdutil.AddJSONFlags(cmd)

	return cmd
}

func runList(ctx context.Context, f *factory.Factory, exporter *cmdutil.Exporter, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
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

	snapshots, err := sm.List(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to list snapshots: %w", err)
	}

	if exporter.Enabled() {
		items := make([]snapshotJSON, 0, len(snapshots))
		for _, snap := range snapshots {
			items = append(items, snapshotJSON{
				Name:         snap.Name,
				CreationTime: snap.CreationTime,
				State:        snap.State,
				Current:      snap.Current,
			})
		}
		return exporter.Write(f.IO.Out, items)
	}

	if len(snapshots) == 0 {
		return &cmdutil.NoResultsError{Message: fmt.Sprintf("no snapshots for instance %q", name)}
	}

	f.IO.StartPager()
	defer f.IO.StopPager()

	out := f.IO.Out

	tp := tableprinter.New(out, f.ColorScheme, f.IO.IsTerminal())
	tp.AddHeader("NAME", "CREATED", "STATE", "CURRENT")

	for _, snap := range snapshots {
		current := ""
		if snap.Current {
			current = "*"
		}
		tp.AddRow(snap.Name, snap.CreationTime, snap.State, current)
	}
	tp.Render()

	fmt.Fprintf(out, "\nTotal: %d snapshot(s)\n", len(snapshots))
	return nil
}
