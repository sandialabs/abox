package add

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/forward/shared"

	"github.com/spf13/cobra"
)

// Options holds the options for the forward add command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Mapping string
	Reverse bool
}

// NewCmdAdd creates a new forward add command.
func NewCmdAdd(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "add <instance> <host-port>:<guest-port>",
		Short: "Add a port forward between host and guest",
		Long: `Add a port forward between the host and guest using SSH tunneling.

By default, forwards host port to guest (access guest service from host).
Use --reverse to forward guest port to host (access host service from guest).`,
		Example: `  abox forward add dev 8080:80           # Access guest port 80 at localhost:8080
  abox forward add dev 3000:3000         # Forward Node.js app from guest
  abox forward add dev 8000:8000 -R      # Access host port 8000 from guest`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.Mapping = args[1]
			if runF != nil {
				return runF(opts)
			}
			return runAdd(f, args[0], args[1], opts.Reverse)
		},
	}

	cmd.Flags().BoolVarP(&opts.Reverse, "reverse", "R", false, "Reverse forward (guest accesses host service)")

	return cmd
}

func parsePortSpec(spec string) (hostPort, guestPort int, err error) {
	parts := strings.Split(spec, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port spec %q; expected <host-port>:<guest-port>", spec)
	}

	hostPort, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid host port %q: %w", parts[0], err)
	}

	guestPort, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid guest port %q: %w", parts[1], err)
	}

	if hostPort < 1 || hostPort > 65535 {
		return 0, 0, fmt.Errorf("host port %d out of range (1-65535)", hostPort)
	}
	if guestPort < 1 || guestPort > 65535 {
		return 0, 0, fmt.Errorf("guest port %d out of range (1-65535)", guestPort)
	}

	return hostPort, guestPort, nil
}

func runAdd(f *factory.Factory, name, portSpec string, reverse bool) error {
	hostPort, guestPort, err := parsePortSpec(portSpec)
	if err != nil {
		return err
	}

	be, err := f.BackendFor(name)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	inst, paths, err := instance.LoadRunning(name, be.VM())
	if err != nil {
		return err
	}

	ip, err := instance.GetIP(inst, be.VM())
	if err != nil {
		return err
	}

	// Check if host port is already forwarded
	existing, err := shared.FindForwardByHostPort(paths.Instance, hostPort)
	if err != nil {
		return fmt.Errorf("failed to check existing forwards: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("host port %d is already forwarded to guest port %d", hostPort, existing.GuestPort)
	}

	// Record forward entry
	entry := shared.ForwardEntry{
		HostPort:  hostPort,
		GuestPort: guestPort,
		Reverse:   reverse,
	}

	// Start SSH tunnel
	pid, err := shared.StartTunnel(paths, inst.GetUser(), ip, entry)
	if err != nil {
		return err
	}

	// Save forward with PID
	entry.PID = pid
	entry.CreatedAt = time.Now()

	if err := shared.AddForward(paths.Instance, entry); err != nil {
		logging.Warn("failed to record forward", "error", err, "instance", name)
	}

	if reverse {
		fmt.Fprintf(f.IO.Out, "Reverse forwarding guest:%d -> host:%d (pid %d)\n", guestPort, hostPort, pid)
	} else {
		fmt.Fprintf(f.IO.Out, "Forwarding localhost:%d -> %s:%d (pid %d)\n", hostPort, ip, guestPort, pid)
	}

	logging.AuditInstance(name, logging.ActionForwardAdd, "host_port", hostPort, "guest_port", guestPort, "reverse", reverse)

	return nil
}
