package remove

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
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
		Long:    `Remove a base image from both the user cache and the libvirt image store.`,
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
	userImage := filepath.Join(paths.UserBaseImages, name+".qcow2")
	libvirtImage := filepath.Join(paths.BaseImages, name+".qcow2")

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
		inUse, err := instancesUsingBase(libvirtImage)
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

	// Delete libvirt copy (requires privilege helper + flock)
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
// and deletes the libvirt base image via the privilege helper.
func removeLibvirtCopy(ctx context.Context, opts *Options, name, libvirtImage string) error {
	// Acquire exclusive flock — blocks until any in-progress creates finish
	unlock, err := images.LockBaseImage(libvirtImage, syscall.LOCK_EX)
	if err != nil {
		return fmt.Errorf("failed to lock base image: %w", err)
	}

	// Re-scan under lock (unless --force): authoritative check
	if !opts.Force {
		inUse, err := instancesUsingBase(libvirtImage)
		if err != nil {
			unlock.Close()
			return fmt.Errorf("failed to scan for instances using base image: %w", err)
		}
		if len(inUse) > 0 {
			unlock.Close()
			return fmt.Errorf("base image %q is in use by instances: %s", name, strings.Join(inUse, ", "))
		}
	}

	// Delete via privilege helper
	client, err := opts.Factory.PrivilegeClient()
	if err != nil {
		unlock.Close()
		return fmt.Errorf("failed to get privilege client: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()

	_, err = client.RemoveAll(ctx, &rpc.PathReq{Path: libvirtImage})
	unlock.Close()
	if err != nil {
		return fmt.Errorf("failed to remove libvirt base image: %w", err)
	}
	return nil
}

// qemuImgInfo is the JSON output of qemu-img info.
type qemuImgInfo struct {
	BackingFilename string `json:"backing-filename"`
}

// instancesUsingBase scans all instance disks to find those referencing the given base image.
// TODO: when multiple backends are supported, iterate per-backend storage dir.
func instancesUsingBase(baseImagePath string) ([]string, error) {
	instancesDir := filepath.Join(config.LibvirtImagesDir, "instances")

	entries, err := os.ReadDir(instancesDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read instances directory: %w", err)
	}

	var inUse []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		diskPath := filepath.Join(instancesDir, entry.Name(), "disk.qcow2")
		if _, err := os.Stat(diskPath); os.IsNotExist(err) {
			continue
		}

		cmd := exec.Command("qemu-img", "info", "--output=json", diskPath)
		output, err := cmd.Output()
		if err != nil {
			logging.Debug("failed to inspect disk", "path", diskPath, "error", err)
			continue
		}

		var info qemuImgInfo
		if err := json.Unmarshal(output, &info); err != nil {
			logging.Debug("failed to parse qemu-img output", "path", diskPath, "error", err)
			continue
		}

		if info.BackingFilename == baseImagePath {
			inUse = append(inUse, entry.Name())
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
	for _, dir := range []string{paths.UserBaseImages, paths.BaseImages} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if before, ok := strings.CutSuffix(entry.Name(), ".qcow2"); ok {
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
