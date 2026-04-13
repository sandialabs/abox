package serve

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/monitor"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the monitor serve command.
type Options struct {
	Factory *factory.Factory
	Name    string
}

// NewCmdServe creates a new monitor serve command.
func NewCmdServe(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "serve <instance>",
		Short: "Run the monitor daemon for an instance",
		Long: `Run the monitor daemon in the foreground.

This command is typically spawned by 'abox start' and runs until
the instance is stopped. It can also be run manually for debugging.

The daemon:
  - Reads Tetragon events from the virtio-serial socket
  - Logs events to a file for later viewing
  - Provides a Unix socket API for status queries
  - Handles log rotation automatically`,
		Args:   cobra.ExactArgs(1),
		Hidden: true, // Internal command, not shown in help
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runServe(cmd.Context(), opts, args[0])
		},
	}

	return cmd
}

func runServe(ctx context.Context, _ *Options, name string) error {
	if !config.Exists(name) {
		return fmt.Errorf("instance %q does not exist", name)
	}

	inst, paths, err := config.Load(name)
	if err != nil {
		return err
	}

	// Check if monitoring is enabled
	if !inst.Monitor.Enabled {
		return fmt.Errorf("monitoring is not enabled for instance %q", name)
	}

	// Create server
	server := monitor.NewServer(paths.MonitorSocket, paths.MonitorRPCSocket, paths.MonitorLog)

	// Start server
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("failed to start monitor server: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Monitor daemon started for instance %q\n", name)
	fmt.Fprintf(os.Stderr, "  Virtio socket: %s\n", paths.MonitorSocket)
	fmt.Fprintf(os.Stderr, "  RPC socket: %s\n", paths.MonitorRPCSocket)
	fmt.Fprintf(os.Stderr, "  Event log: %s\n", paths.MonitorLog)

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	signal.Stop(sigCh) // Clean up signal handler

	fmt.Fprintf(os.Stderr, "\nShutting down monitor daemon...\n")
	server.Stop()
	return nil
}
