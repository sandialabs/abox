package serve

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the http serve command.
type Options struct {
	Factory *factory.Factory
	Passive bool
	Name    string
}

// NewCmdServe creates a new http serve command.
func NewCmdServe(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "serve <instance>",
		Short: "Run the HTTP filter daemon for an instance",
		Long: `Run the HTTP filter daemon in the foreground.

This command is typically spawned by 'abox start' and runs until
the instance is stopped. It can also be run manually for debugging.

The daemon:
  - Listens for HTTP/HTTPS proxy requests on the instance's configured port
  - Filters requests against the allowlist
  - Provides a Unix socket API for runtime control
  - Watches the allowlist file for changes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			if runF != nil {
				return runF(opts)
			}
			return runServe(opts, args[0])
		},
	}

	cmd.Flags().BoolVar(&opts.Passive, "passive", false, "Start in passive mode (monitoring only)")

	return cmd
}

func runServe(opts *Options, name string) error {
	setup, err := filterbase.SetupDaemon(name, os.Stderr)
	if err != nil {
		return err
	}
	defer setup.Loader.Stop()

	// Create HTTP proxy server
	server := httpfilter.NewServer(setup.Filter, opts.Passive)

	// Load CA certificate for TLS MITM if enabled
	if setup.Inst.HTTP.MITM {
		if err := server.LoadCA(setup.Paths.CACert, setup.Paths.CAKey); err != nil {
			return fmt.Errorf("failed to load CA certificate: %w (run 'abox remove %s && abox create %s' to regenerate)", err, name, name)
		}
		fmt.Fprintf(os.Stderr, "TLS MITM enabled (domain fronting protection)\n")
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: TLS MITM disabled - domain fronting protection unavailable\n")
	}

	// Initialize profile logger for domain capture (passive mode logs to this)
	if err := server.InitProfileLogger(setup.Paths.ProfileLog); err != nil {
		logging.Warn("failed to initialize profile logger", "error", err, "instance", name)
	}

	// Initialize traffic logger for allow/block decisions
	if err := server.InitTrafficLogger(setup.Paths.HTTPTrafficLog); err != nil {
		logging.Warn("failed to initialize traffic logger", "error", err, "instance", name)
	}
	defer server.CloseTrafficLogger()

	// Start HTTP server
	// Listen on the gateway IP for the HTTP proxy
	listenAddr := fmt.Sprintf("%s:%d", setup.Inst.Gateway, setup.Inst.HTTP.Port)

	if err := server.Start(listenAddr); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}
	defer func() {
		ctx, cancel := httpfilter.ClientContext()
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	fmt.Fprintf(os.Stderr, "HTTP proxy listening on %s:%d\n", setup.Inst.Gateway, server.GetListenPort())

	// Start API server
	api := httpfilter.NewAPIServer(setup.Paths.HTTPSocket, setup.Filter, server, setup.Loader)
	if err := api.Start(); err != nil {
		return fmt.Errorf("failed to start API server: %w", err)
	}
	defer api.Stop()
	fmt.Fprintf(os.Stderr, "API socket: %s\n", setup.Paths.HTTPSocket)

	// Log mode
	mode := "active"
	if opts.Passive {
		mode = "passive"
	}
	fmt.Fprintf(os.Stderr, "Mode: %s\n", mode)
	fmt.Fprintf(os.Stderr, "HTTP filter ready for instance %q\n", name)

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Fprintf(os.Stderr, "\nShutting down HTTP filter...\n")
	return nil
}
