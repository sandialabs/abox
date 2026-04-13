package remove

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/forward/shared"

	"github.com/spf13/cobra"
)

// Options holds the options for the forward remove command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Port    string
}

// NewCmdRemove creates a new forward remove command.
func NewCmdRemove(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:     "remove <instance> <host-port>",
		Aliases: []string{"rm"},
		Short:   "Remove a port forward",
		Long:    `Remove a port forward and stop the SSH tunnel.`,
		Example: `  abox forward remove dev 8080     # Stop forwarding port 8080
  abox forward rm dev 3000         # Stop forwarding port 3000`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Port = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runRemove(f, args[0], args[1])
		},
	}

	return cmd
}

func runRemove(f *factory.Factory, name, portStr string) error {
	hostPort, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid host port %q: %w", portStr, err)
	}

	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	_, paths, err := config.Load(name)
	if err != nil {
		return err
	}

	// Find the forward
	entry, err := shared.FindForwardByHostPort(paths.Instance, hostPort)
	if err != nil {
		return fmt.Errorf("failed to load forwards: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("no forward found for host port %d", hostPort)
	}

	// Kill the SSH tunnel process
	if shared.IsPIDRunning(entry.PID) {
		if err := syscall.Kill(entry.PID, syscall.SIGTERM); err != nil {
			logging.Warn("failed to kill forward process", "error", err, "instance", name, "pid", entry.PID)
		}
	}

	// Remove from forwards file
	if err := shared.RemoveForward(paths.Instance, hostPort); err != nil {
		return fmt.Errorf("failed to update forwards file: %w", err)
	}

	if entry.Reverse {
		fmt.Fprintf(f.IO.Out, "Removed reverse forward guest:%d -> host:%d\n", entry.GuestPort, hostPort)
	} else {
		fmt.Fprintf(f.IO.Out, "Removed forward localhost:%d -> guest:%d\n", hostPort, entry.GuestPort)
	}

	logging.AuditInstance(name, logging.ActionForwardRemove, "host_port", hostPort, "guest_port", entry.GuestPort, "reverse", entry.Reverse)

	return nil
}
