package down

import (
	"context"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/tui"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/remove"
	"github.com/sandialabs/abox/pkg/cmd/stop"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the down command.
type Options struct {
	Factory *factory.Factory
	Dir     string
	Remove  bool
	Force   bool
}

// NewCmdDown creates a new down command.
func NewCmdDown(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop an instance defined in abox.yaml",
		Long: `Stop an instance defined in abox.yaml.

This command reads abox.yaml from the current directory (or specified directory)
and stops the corresponding instance.

Use --remove to also delete the instance and all its data.`,
		Example: `  abox down                                # Stop the instance defined in abox.yaml
  abox down --remove                       # Stop and delete the instance
  abox down -d /path/to/project            # Use abox.yaml from another directory`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return runDown(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.Dir, "dir", "d", "", "Directory containing abox.yaml (default: current directory)")
	cmd.Flags().BoolVar(&opts.Remove, "remove", false, "Also remove the instance (delete all data)")
	cmd.Flags().BoolVar(&opts.Remove, "rm", false, "Alias for --remove")
	_ = cmd.Flags().MarkHidden("rm")
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Skip confirmation prompt when using --remove")

	return cmd
}

func runDown(ctx context.Context, opts *Options) error {
	// Load abox.yaml
	box, boxDir, err := boxfile.Load(opts.Dir)
	if err != nil {
		return err
	}

	// Ensure we have a factory to share between stop and remove
	factory.Ensure(&opts.Factory)
	f := opts.Factory

	// Check if instance exists
	if !config.Exists(box.Name) {
		fmt.Fprintf(f.IO.Out, "Instance %q does not exist.\n", box.Name)
		return nil
	}

	if f.IO.IsTerminal() {
		return runDownTUI(ctx, opts, box)
	}
	return runDownPlain(ctx, opts, box, boxDir)
}

// ---------------------------------------------------------------------------
// Plain text path (non-TTY or pipe)
// ---------------------------------------------------------------------------

func runDownPlain(ctx context.Context, opts *Options, box *boxfile.Boxfile, boxDir string) error {
	w := opts.Factory.IO.Out
	fmt.Fprintf(w, "Using abox.yaml from %s\n", boxDir)
	fmt.Fprintf(w, "Instance: %s\n\n", box.Name)

	if opts.Remove && !opts.Force {
		fmt.Fprintf(opts.Factory.IO.ErrOut, "This will permanently delete instance %q and all its data.\n", box.Name)
		if !opts.Factory.Prompter.Confirm("Are you sure? [y/N] ") {
			return &cmdutil.ErrCancel{}
		}
	}

	if err := doDown(ctx, opts, box, tui.NoopNotifier{}); err != nil {
		return err
	}

	verb := "stopped"
	if opts.Remove {
		verb = "removed"
	}
	fmt.Fprintf(w, "\nInstance %q %s.\n", box.Name, verb)
	return nil
}

// ---------------------------------------------------------------------------
// TUI path
// ---------------------------------------------------------------------------

func runDownTUI(ctx context.Context, opts *Options, box *boxfile.Boxfile) error {
	// Pre-TUI: confirmation prompt for --remove (unless --force)
	if opts.Remove && !opts.Force {
		fmt.Fprintf(opts.Factory.IO.ErrOut, "This will permanently delete instance %q and all its data.\n", box.Name)
		if !opts.Factory.Prompter.Confirm("Are you sure? [y/N] ") {
			return &cmdutil.ErrCancel{}
		}
	}

	// Pre-authenticate sudo before TUI takes over the terminal.
	// Only needed when removing; stop handles privilege lazily.
	if opts.Remove {
		if _, err := opts.Factory.PrivilegeClientFor(box.Name); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	// Build step list
	var steps []tui.Step
	steps = append(steps, tui.Step{Name: "Stop instance"})
	if opts.Remove {
		steps = append(steps, tui.Step{Name: "Remove instance"})
	}

	successMsg := fmt.Sprintf("Instance %q stopped.", box.Name)
	if opts.Remove {
		successMsg = fmt.Sprintf("Instance %q removed.", box.Name)
	}
	done := tui.DoneConfig{
		SuccessMsg: successMsg,
	}

	return tui.Run("abox down: "+box.Name, steps, done, func(out io.Writer, errOut io.Writer, notify tui.PhaseNotifier) error {
		f := opts.Factory
		f.IO.SetOutputSplit(out, errOut)
		defer f.IO.RestoreOutput()
		old := logging.StderrWriter().Swap(errOut)
		defer logging.StderrWriter().Swap(old)
		return doDown(ctx, opts, box, notify)
	})
}

// ---------------------------------------------------------------------------
// Unified work function
// ---------------------------------------------------------------------------

func doDown(ctx context.Context, opts *Options, box *boxfile.Boxfile, notify tui.PhaseNotifier) error {
	// Phase 0: Stop
	notify.PhaseStart(0)
	if err := stop.Run(ctx, &stop.Options{Factory: opts.Factory, Brief: true}, box.Name); err != nil {
		notify.PhaseDone(0, err)
		return fmt.Errorf("failed to stop instance: %w", err)
	}
	notify.PhaseDone(0, nil)

	// Phase 1: Remove (optional)
	if opts.Remove {
		notify.PhaseStart(1)
		if err := remove.Run(ctx, &remove.Options{Factory: opts.Factory, Force: true, SkipDaemonStop: true, Brief: true}, box.Name); err != nil {
			notify.PhaseDone(1, err)
			return fmt.Errorf("failed to remove instance: %w", err)
		}
		notify.PhaseDone(1, nil)
	}

	var auditArgs []any
	if opts.Remove {
		auditArgs = append(auditArgs, "remove", true)
	}
	logging.AuditInstance(box.Name, logging.ActionDown, auditArgs...)

	return nil
}
