package restart

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/start"
	"github.com/sandialabs/abox/pkg/cmd/stop"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the restart command.
type Options struct {
	Factory *factory.Factory
	Force   bool     // Pass through to stop (force stop)
	Names   []string // Instance names to restart
}

// NewCmdRestart creates a new restart command.
func NewCmdRestart(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "restart <name...>",
		Short: "Restart one or more abox instances",
		Long: `Stop and then start one or more running instances.

Equivalent to running 'abox stop' followed by 'abox start'. Use after
'abox config edit' to apply configuration changes that require a VM restart.`,
		Example: `  abox restart dev                         # Restart a single instance
  abox restart dev -f                      # Force stop, then start
  abox restart dev staging                 # Restart multiple instances`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completion.Repeat(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Names = args
			if runF != nil {
				return runF(opts)
			}
			ctx := cmd.Context()
			return cmdutil.ForEach(args, func(name string) error {
				return runRestart(ctx, opts, name)
			})
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Force stop (don't wait for graceful shutdown)")

	return cmd
}

func runRestart(ctx context.Context, opts *Options, name string) error {
	factory.Ensure(&opts.Factory)
	w := opts.Factory.IO.Out

	fmt.Fprintf(w, "Restarting instance %q...\n", name)

	if err := stop.Run(ctx, &stop.Options{Factory: opts.Factory, Force: opts.Force, Brief: true}, name); err != nil {
		return fmt.Errorf("failed to stop instance: %w", err)
	}

	if err := start.Run(ctx, &start.Options{Factory: opts.Factory, Brief: true}, name); err != nil {
		return fmt.Errorf("failed to start instance: %w", err)
	}

	fmt.Fprintf(w, "\nInstance %q restarted.\n", name)

	logging.AuditInstance(name, logging.ActionInstanceRestart,
		"force", opts.Force,
	)

	return nil
}
