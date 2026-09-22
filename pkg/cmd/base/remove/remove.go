package remove

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/qemuimg"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the base remove command.
type Options struct {
	Factory *factory.Factory
	Force   bool
	Name    string
}

// NewCmdRemove creates a new base remove command.
func NewCmdRemove(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:     "remove <name>",
		Aliases: []string{"rm"},
		Short:   "Remove a base image",
		Long:    `Remove a base image from both the user download cache and the user-owned base-image store.`,
		Example: `  abox base remove ubuntu-22.04            # Remove with confirmation
  abox base rm ubuntu-22.04 -f            # Skip confirmation`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeBaseImages,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runRemove(cmd.Context(), opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Skip in-use check and confirmation prompt")

	return cmd
}

func runRemove(ctx context.Context, opts *Options) error {
	factory.Ensure(&opts.Factory)

	paths, err := config.GetPaths("")
	if err != nil {
		return err
	}

	name := opts.Name
	userImage := filepath.Join(paths.UserBaseImages, config.UserBaseImageName(name))
	libvirtImage := filepath.Join(paths.BaseImages, config.UserBaseImageName(name))

	// Check if image exists in either location
	_, userErr := os.Stat(userImage)
	_, libvirtErr := os.Stat(libvirtImage)

	if os.IsNotExist(userErr) && os.IsNotExist(libvirtErr) {
		return fmt.Errorf("base image %q not found", name)
	}

	out := opts.Factory.IO.Out
	hasLibvirtCopy := libvirtErr == nil

	// Early in-use scan (unless --force): check if any instance disks reference this base image
	if !opts.Force && hasLibvirtCopy {
		inUse, err := instancesUsingBase(ctx, libvirtImage)
		if err != nil {
			logging.Debug("failed to scan for instances using base image", "error", err)
		} else if len(inUse) > 0 {
			return &cmdutil.ErrHint{
				Err:  fmt.Errorf("base image %q is in use by instances: %s", name, strings.Join(inUse, ", ")),
				Hint: "Use --force to skip this check",
			}
		}
	}

	// Confirmation prompt (unless --force)
	if !opts.Force {
		if !opts.Factory.Prompter.Confirm(fmt.Sprintf("Remove base image %q? [y/N] ", name)) {
			return &cmdutil.ErrCancel{}
		}
	}

	// Delete user cache copy
	if userErr == nil {
		if err := os.Remove(userImage); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove user cache copy: %w", err)
		}
		fmt.Fprintf(out, "Removed %s\n", userImage)
	}

	// Delete the stored base-image copy. Storage is user-owned, so this needs no
	// privilege helper — only an flock to serialize against concurrent creates.
	if hasLibvirtCopy {
		if err := removeLibvirtCopy(ctx, opts, name, libvirtImage); err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed %s\n", libvirtImage)
	}

	logging.Audit(logging.ActionBaseRemove, "action", logging.ActionBaseRemove, "name", name)

	fmt.Fprintf(out, "Base image %q removed.\n", name)
	return nil
}

// removeLibvirtCopy acquires an exclusive flock, re-scans for in-use instances,
// and deletes the stored base image from the user-owned base-image store (the
// path is still named libvirtImage for historical reasons). Storage is
// user-owned, so this runs unprivileged (no privilege helper).
func removeLibvirtCopy(ctx context.Context, opts *Options, name, libvirtImage string) error {
	// Acquire exclusive flock — blocks until any in-progress creates finish
	unlock, err := images.LockBaseImage(libvirtImage, images.LockExclusive)
	if err != nil {
		return fmt.Errorf("failed to lock base image: %w", err)
	}

	// Re-scan under lock (unless --force): authoritative check
	if !opts.Force {
		inUse, err := instancesUsingBase(ctx, libvirtImage)
		if err != nil {
			unlock.Close()
			return fmt.Errorf("failed to scan for instances using base image: %w", err)
		}
		if len(inUse) > 0 {
			unlock.Close()
			return fmt.Errorf("base image %q is in use by instances: %s", name, strings.Join(inUse, ", "))
		}
	}

	// Delete the stored base image. Storage is user-owned, so this runs
	// unprivileged.
	err = os.RemoveAll(libvirtImage)
	unlock.Close()
	if err != nil {
		return fmt.Errorf("failed to remove base image: %w", err)
	}
	return nil
}

// instancesUsingBase returns the names of all instances whose disk backs onto the
// given base image. It enumerates every instance via config.Load, which resolves
// each disk's real location — so it covers instances with a custom storage_dir or
// legacy root-owned storage, not just the default storage directory.
func instancesUsingBase(ctx context.Context, baseImagePath string) ([]string, error) {
	names, err := config.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list instances: %w", err)
	}

	var inUse []string
	for _, name := range names {
		_, paths, err := config.Load(name)
		if err != nil {
			logging.Debug("skipping unreadable instance during base in-use scan", "instance", name, "error", err)
			continue
		}
		if _, err := os.Stat(paths.Disk); err != nil {
			continue
		}
		backing, err := qemuimg.BackingFile(ctx, paths.Disk)
		if err != nil {
			logging.Debug("failed to inspect disk", "path", paths.Disk, "error", err)
			continue
		}
		if backing == baseImagePath {
			inUse = append(inUse, name)
		}
	}

	return inUse, nil
}

// completeBaseImages provides tab completion for base image names.
func completeBaseImages(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	paths, err := config.GetPaths("")
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	seen := make(map[string]bool)
	var names []string

	// Scan user cache
	ext := config.UserBaseImageExt()
	for _, dir := range []string{paths.UserBaseImages, paths.BaseImages} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if before, ok := strings.CutSuffix(entry.Name(), ext); ok {
				name := before
				if !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}

	return names, cobra.ShellCompDirectiveNoFileComp
}
