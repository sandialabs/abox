package prune

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/remove"

	"github.com/spf13/cobra"
)

// Options holds the options for the prune command.
type Options struct {
	Factory *factory.Factory
	DryRun  bool
	Force   bool
}

// NewCmdPrune creates a new prune command.
func NewCmdPrune(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "prune [flags]",
		Short: "Remove stale instances and unused base images",
		Long: `Remove stale instances and unused base images to reclaim disk space.

Refuses to run unless -f (--force) or -n (--dry-run) is given.
Removes stopped, shutdown, and crashed instances plus base images
not referenced by any instance.`,
		Example: `  abox prune -n          # Preview what would be removed
  abox prune -f          # Remove stale instances and unused images`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.Force && !opts.DryRun {
				return errors.New("refusing to prune without -f (--force) or -n (--dry-run)")
			}
			if runF != nil {
				return runF(opts)
			}
			return runPrune(cmd.Context(), opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.DryRun, "dry-run", "n", false, "Preview what would be removed without deleting")
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Actually remove items")

	return cmd
}

func runPrune(ctx context.Context, opts *Options) error {
	factory.Ensure(&opts.Factory)
	w := opts.Factory.IO.Out

	// Dry-run takes precedence when both flags are set (matches git clean -fn).
	if opts.DryRun {
		opts.Force = false
	}

	// Snapshot referenced base images BEFORE removing any instances so that
	// dry-run output accurately predicts what force mode will delete.
	referenced, err := referencedBaseImages()
	if err != nil {
		return err
	}

	var foundAnything bool
	var instancesRemoved, imagesRemoved int

	found, removed, err := pruneInstances(ctx, opts)
	if err != nil {
		return err
	}
	foundAnything = foundAnything || found
	instancesRemoved = removed

	found, removed, err = pruneImages(opts, referenced)
	if err != nil {
		return err
	}
	foundAnything = foundAnything || found
	imagesRemoved = removed

	if !foundAnything {
		fmt.Fprintln(w, "Nothing to prune.")
	} else if !opts.DryRun && (instancesRemoved > 0 || imagesRemoved > 0) {
		fmt.Fprintf(w, "\nPruned %d instance(s) and %d image(s).\n", instancesRemoved, imagesRemoved)
	}

	return nil
}

// isStale returns true if the VM state indicates the instance is not actively used.
func isStale(state backend.VMState) bool {
	return state == backend.VMStateStopped || state == backend.VMStateShutdown || state == backend.VMStateCrashed
}

// findStaleInstances returns instance names whose VMs are stopped, shutdown, or crashed.
func findStaleInstances(opts *Options, names []string) []string {
	var stopped []string
	var backendErrors int
	for _, name := range names {
		be, err := opts.Factory.BackendFor(name)
		if err != nil {
			fmt.Fprintf(opts.Factory.IO.ErrOut, "warning: cannot check state of %s: %v\n", name, err)
			backendErrors++
			continue
		}
		if isStale(be.VM().State(name)) {
			stopped = append(stopped, name)
		}
	}
	if backendErrors > 0 && backendErrors == len(names) {
		fmt.Fprintf(opts.Factory.IO.ErrOut, "warning: could not determine state of any instance (backend unavailable)\n")
	}
	return stopped
}

// pruneInstances finds and removes stale instances. Returns whether candidates
// were found and how many were successfully removed.
func pruneInstances(ctx context.Context, opts *Options) (bool, int, error) {
	w := opts.Factory.IO.Out

	names, err := config.List()
	if err != nil {
		return false, 0, fmt.Errorf("failed to list instances: %w", err)
	}

	stopped := findStaleInstances(opts, names)
	if len(stopped) == 0 {
		return false, 0, nil
	}

	if opts.DryRun {
		fmt.Fprintf(w, "Would remove %d stale instance(s):\n", len(stopped))
	} else {
		fmt.Fprintf(w, "Stale instances (%d):\n", len(stopped))
	}
	for _, name := range stopped {
		fmt.Fprintf(w, "  - %s\n", name)
	}

	if opts.DryRun {
		return true, 0, nil
	}

	fmt.Fprintln(w)
	removed := 0
	for _, name := range stopped {
		// Re-check state to avoid removing an instance started since discovery.
		if be, err := opts.Factory.BackendFor(name); err == nil {
			state := be.VM().State(name)
			if state == backend.VMStateRunning || state == backend.VMStatePaused {
				fmt.Fprintf(opts.Factory.IO.ErrOut, "  skipping %s: state changed to %s\n", name, state)
				continue
			}
		}

		fmt.Fprintf(w, "Removing %s...\n", name)
		if err := remove.Run(ctx, &remove.Options{Factory: opts.Factory, Force: true, Brief: true}, name); err != nil {
			fmt.Fprintf(opts.Factory.IO.ErrOut, "  warning: failed to remove %s: %v\n", name, err)
			continue
		}
		removed++
	}

	if removed > 0 {
		logging.Audit("pruned stale instances", "action", logging.ActionPrune,
			"type", "instances",
			"count", removed,
		)
	}

	return true, removed, nil
}

// pruneImages finds and removes base images not referenced by any instance.
// The referenced set must be computed before any instances are removed to
// ensure dry-run output matches force behavior.
func pruneImages(opts *Options, referenced map[string]bool) (bool, int, error) {
	w := opts.Factory.IO.Out

	paths, err := config.GetPaths("")
	if err != nil {
		return false, 0, err
	}

	unused, err := findUnusedImages(paths.UserBaseImages, referenced)
	if err != nil {
		return false, 0, err
	}
	if len(unused) == 0 {
		return false, 0, nil
	}

	if opts.DryRun {
		fmt.Fprintf(w, "Would remove %d unused base image(s):\n", len(unused))
	} else {
		fmt.Fprintf(w, "Unused base images (%d):\n", len(unused))
	}
	var totalBytes int64
	for _, name := range unused {
		imagePath := filepath.Join(paths.UserBaseImages, name+".qcow2")
		info, err := os.Stat(imagePath)
		size := "unknown size"
		if err == nil {
			size = formatSize(info.Size())
			totalBytes += info.Size()
		}
		fmt.Fprintf(w, "  - %s (%s)\n", name, size)
	}
	if totalBytes > 0 {
		fmt.Fprintf(w, "  Total: %s reclaimable\n", formatSize(totalBytes))
	}

	if opts.DryRun {
		return true, 0, nil
	}

	removed := removeUnusedImages(opts, paths.UserBaseImages, unused)
	return true, removed, nil
}

// referencedBaseImages returns the set of base image names referenced by existing instances.
func referencedBaseImages() (map[string]bool, error) {
	referenced := make(map[string]bool)
	names, err := config.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list instances: %w", err)
	}
	for _, name := range names {
		inst, _, err := config.Load(name)
		if err != nil {
			return nil, fmt.Errorf("cannot determine base image for instance %q (config unreadable): %w", name, err)
		}
		referenced[inst.Base] = true
	}
	return referenced, nil
}

// findUnusedImages scans the base images directory for images not in the referenced set.
func findUnusedImages(baseDir string, referenced map[string]bool) ([]string, error) {
	entries, err := os.ReadDir(baseDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read base images directory: %w", err)
	}

	var unused []string
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".qcow2")
		if !ok {
			continue
		}
		if !referenced[name] {
			unused = append(unused, name)
		}
	}
	return unused, nil
}

// removeUnusedImages deletes the given base images and returns how many were removed.
func removeUnusedImages(opts *Options, baseDir string, unused []string) int {
	w := opts.Factory.IO.Out
	fmt.Fprintln(w)
	removed := 0
	for _, name := range unused {
		imagePath := filepath.Join(baseDir, name+".qcow2")
		if err := os.Remove(imagePath); err != nil {
			fmt.Fprintf(opts.Factory.IO.ErrOut, "  warning: failed to remove %s: %v\n", imagePath, err)
			continue
		}
		fmt.Fprintf(w, "Removed %s\n", imagePath)
		removed++
	}

	if removed > 0 {
		logging.Audit("pruned unused images", "action", logging.ActionImagePrune,
			"type", "images",
			"count", removed,
		)
	}

	return removed
}

func formatSize(bytes int64) string {
	const (
		mb = 1024 * 1024
		gb = 1024 * mb
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
