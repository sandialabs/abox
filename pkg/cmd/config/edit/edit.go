package edit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the edit command.
type Options struct {
	Factory  *factory.Factory
	CPUs     int
	Memory   int
	Disk     string
	Upstream string
	Name     string
}

// NewCmdEdit creates a new config edit command.
func NewCmdEdit(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "edit <instance>",
		Short: "Edit instance configuration",
		Long: `Edit the configuration for an abox instance.

Only the following fields can be modified:
  --cpus      Number of CPUs (requires VM restart)
  --memory    Memory in MB (requires VM restart)
  --disk      Disk size (can only grow, not shrink)
  --upstream  Upstream DNS server (requires dnsfilter restart)

Fields like subnet, gateway, bridge, and ports cannot be changed
after instance creation.`,
		Example: `  abox config edit dev --cpus 4            # Change CPU count
  abox config edit dev --memory 8192       # Change memory (MB)
  abox config edit dev -c 4 -m 8192       # Change multiple fields at once`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runEdit(cmd, opts, args[0])
		},
	}

	cmd.Flags().IntVarP(&opts.CPUs, "cpus", "c", 0, "Number of CPUs")
	cmd.Flags().IntVarP(&opts.Memory, "memory", "m", 0, "Memory in MB")
	cmd.Flags().StringVar(&opts.Disk, "disk", "", "Disk size (e.g., 30G)")
	cmd.Flags().StringVarP(&opts.Upstream, "upstream", "u", "", "Upstream DNS server")

	return cmd
}

func runEdit(cmd *cobra.Command, opts *Options, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	inst, paths, err := config.Load(name)
	if err != nil {
		return err
	}

	changed := false
	var changes []string

	if cmd.Flags().Changed("cpus") {
		if err := validation.ValidateResourceLimits(opts.CPUs, inst.Memory); err != nil {
			return cmdutil.FlagErrorf("%s", err)
		}
		changes = append(changes, fmt.Sprintf("cpus: %d -> %d", inst.CPUs, opts.CPUs))
		inst.CPUs = opts.CPUs
		changed = true
	}

	if cmd.Flags().Changed("memory") {
		if err := validation.ValidateResourceLimits(inst.CPUs, opts.Memory); err != nil {
			return cmdutil.FlagErrorf("%s", err)
		}
		changes = append(changes, fmt.Sprintf("memory: %d -> %d MB", inst.Memory, opts.Memory))
		inst.Memory = opts.Memory
		changed = true
	}

	if cmd.Flags().Changed("disk") {
		if err := validation.ValidateDiskSize(opts.Disk); err != nil {
			return cmdutil.FlagErrorf("%s", err)
		}
		if err := validateDiskSize(opts.Disk, inst.Disk); err != nil {
			return err
		}
		changes = append(changes, fmt.Sprintf("disk: %s -> %s", inst.Disk, opts.Disk))
		inst.Disk = opts.Disk
		changed = true
	}

	if cmd.Flags().Changed("upstream") {
		normalized, err := validation.NormalizeUpstreamDNS(opts.Upstream)
		if err != nil {
			return fmt.Errorf("invalid upstream DNS: %w", err)
		}
		changes = append(changes, fmt.Sprintf("dns.upstream: %s -> %s", inst.DNS.Upstream, normalized))
		inst.DNS.Upstream = normalized
		changed = true
	}

	if !changed {
		return cmdutil.FlagErrorf("no changes specified; use --cpus, --memory, --disk, or --upstream")
	}

	if err := config.Save(inst, paths); err != nil {
		return err
	}

	w := opts.Factory.IO.Out
	fmt.Fprintf(w, "Updated %s:\n", name)
	for _, c := range changes {
		fmt.Fprintf(w, "  %s\n", c)
	}

	logging.AuditInstance(name, logging.ActionConfigEdit, "changes", strings.Join(changes, "; "))

	return nil
}

// validateDiskSize checks that the new disk size is valid and not smaller than current.
func validateDiskSize(newSize, currentSize string) error {
	newBytes, err := parseDiskSize(newSize)
	if err != nil {
		return fmt.Errorf("invalid disk size %q: %w", newSize, err)
	}

	currentBytes, err := parseDiskSize(currentSize)
	if err != nil {
		return nil //nolint:nilerr // unparseable current size; skip validation and allow the change
	}

	if newBytes < currentBytes {
		return fmt.Errorf("disk size can only be increased (current: %s)", currentSize)
	}

	return nil
}

// parseDiskSize parses a size string like "20G" into bytes.
func parseDiskSize(size string) (int64, error) {
	size = strings.TrimSpace(size)
	if size == "" {
		return 0, errors.New("empty size")
	}

	multiplier := int64(1)
	suffix := size[len(size)-1]

	switch suffix {
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		size = size[:len(size)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		size = size[:len(size)-1]
	case 'K', 'k':
		multiplier = 1024
		size = size[:len(size)-1]
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
		size = size[:len(size)-1]
	}

	value, err := strconv.ParseInt(size, 10, 64)
	if err != nil {
		return 0, err
	}

	return value * multiplier, nil
}
