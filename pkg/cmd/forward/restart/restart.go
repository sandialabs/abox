package restart

import (
	"fmt"
	"io"
	"strconv"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/forward/shared"

	"github.com/spf13/cobra"
)

// Options holds the options for the forward restart command.
type Options struct {
	Factory *factory.Factory
	Name    string
	Port    string
}

// NewCmdRestart creates a new forward restart command.
func NewCmdRestart(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{Factory: f}

	cmd := &cobra.Command{
		Use:   "restart <instance> [host-port]",
		Short: "Restart inactive port forwards",
		Long: `Restart inactive SSH tunnel port forwards.

When a host port is specified, only that forward is restarted.
When no host port is given, all inactive forwards are restarted.`,
		Example: `  abox forward restart dev         # Restart all inactive forwards
  abox forward restart dev 8080    # Restart forward on host port 8080`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completion.Sequence(completion.RunningInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if len(args) == 2 {
				opts.Port = args[1]
			}
			if runF != nil {
				return runF(opts)
			}
			w := f.IO.Out
			if len(args) == 2 {
				return runRestartOne(w, f, args[0], args[1])
			}
			return runRestartAll(w, f, args[0])
		},
	}

	return cmd
}

func runRestartOne(w io.Writer, f *factory.Factory, name, portStr string) error {
	hostPort, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid host port %q: %w", portStr, err)
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

	entry, err := shared.FindForwardByHostPort(paths.Instance, hostPort)
	if err != nil {
		return fmt.Errorf("failed to load forwards: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("no forward found for host port %d", hostPort)
	}

	if shared.IsPIDRunning(entry.PID) {
		fmt.Fprintf(w, "Forward on host port %d is already active (pid %d)\n", hostPort, entry.PID)
		return nil
	}

	pid, err := shared.StartTunnel(paths, inst.GetUser(), ip, *entry)
	if err != nil {
		return err
	}

	if err := shared.UpdateForwardPID(paths.Instance, hostPort, pid); err != nil {
		return fmt.Errorf("failed to update forward PID: %w", err)
	}

	if entry.Reverse {
		fmt.Fprintf(w, "Restarted reverse forward guest:%d -> host:%d (pid %d)\n", entry.GuestPort, entry.HostPort, pid)
	} else {
		fmt.Fprintf(w, "Restarted forward localhost:%d -> guest:%d (pid %d)\n", entry.HostPort, entry.GuestPort, pid)
	}

	logging.AuditInstance(name, logging.ActionForwardRestart, "host_port", hostPort, "guest_port", entry.GuestPort, "reverse", entry.Reverse)

	return nil
}

func runRestartAll(w io.Writer, f *factory.Factory, name string) error {
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

	forwards, err := shared.LoadForwards(paths.Instance)
	if err != nil {
		return fmt.Errorf("failed to load forwards: %w", err)
	}

	if len(forwards.Forwards) == 0 {
		fmt.Fprintf(w, "No port forwards for %s\n", name)
		return nil
	}

	restarted := 0
	for _, entry := range forwards.Forwards {
		if shared.IsPIDRunning(entry.PID) {
			fmt.Fprintf(w, "Forward on host port %d is already active (pid %d), skipping\n", entry.HostPort, entry.PID)
			continue
		}

		pid, err := shared.StartTunnel(paths, inst.GetUser(), ip, entry)
		if err != nil {
			fmt.Fprintf(w, "Failed to restart forward on host port %d: %v\n", entry.HostPort, err)
			continue
		}

		if err := shared.UpdateForwardPID(paths.Instance, entry.HostPort, pid); err != nil {
			fmt.Fprintf(w, "Failed to update PID for host port %d: %v\n", entry.HostPort, err)
			continue
		}

		if entry.Reverse {
			fmt.Fprintf(w, "Restarted reverse forward guest:%d -> host:%d (pid %d)\n", entry.GuestPort, entry.HostPort, pid)
		} else {
			fmt.Fprintf(w, "Restarted forward localhost:%d -> guest:%d (pid %d)\n", entry.HostPort, entry.GuestPort, pid)
		}

		logging.AuditInstance(name, logging.ActionForwardRestart, "host_port", entry.HostPort, "guest_port", entry.GuestPort, "reverse", entry.Reverse)
		restarted++
	}

	if restarted == 0 {
		fmt.Fprintln(w, "No inactive forwards to restart")
	}

	return nil
}
