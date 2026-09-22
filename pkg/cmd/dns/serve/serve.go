package serve

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// Options holds the options for the dns serve command.
type Options struct {
	Factory *factory.Factory
	Passive bool
	Name    string
}

// NewCmdServe creates a new dns serve command.
func NewCmdServe(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "serve <instance>",
		Short: "Run the DNS filter daemon for an instance",
		Long: `Run the DNS filter daemon in the foreground.

This command is typically spawned by 'abox start' and runs until
the instance is stopped. It can also be run manually for debugging.

The daemon:
  - Listens for DNS queries on the instance's configured port
  - Filters queries against the allowlist
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

	// Create DNS server
	server, err := dnsfilter.NewServer(setup.Filter, setup.Inst.DNS.Upstream, opts.Passive)
	if err != nil {
		return fmt.Errorf("failed to create DNS server: %w", err)
	}

	// Apply the opt-in private-target allow-list (rebinding policy, shared with
	// the HTTP proxy). An invalid CIDR must fail closed, so surface it.
	if err := server.SetAllowPrivateTargets(setup.Inst.HTTP.AllowPrivateTargets); err != nil {
		return fmt.Errorf("invalid http.allow_private_targets: %w", err)
	}

	// Initialize profile logger for domain capture (passive mode logs to this)
	if err := server.InitProfileLogger(setup.Paths.ProfileLog); err != nil {
		logging.Warn("failed to initialize profile logger", "error", err, "instance", name)
	}

	// Initialize traffic logger for allow/block decisions
	if err := server.InitTrafficLogger(setup.Paths.DNSTrafficLog); err != nil {
		logging.Warn("failed to initialize traffic logger", "error", err, "instance", name)
	}
	defer server.CloseTrafficLogger()

	// Bind address depends on the platform's DNS redirect target: on Linux the
	// iptables REDIRECT sends packets to the bridge/gateway IP, while on macOS the
	// pfctl rdr rule redirects guest DNS to 127.0.0.1. The seam picks the right one.
	bindHost := filterbase.DNSListenAddress(setup.Inst.Gateway)
	listenAddr := fmt.Sprintf("%s:%d", bindHost, setup.Inst.DNS.Port)

	dnsServer, err := server.Start(listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start DNS server: %w", err)
	}
	defer func() { _ = dnsServer.Shutdown() }()

	fmt.Fprintf(os.Stderr, "DNS server listening on %s:%d (UDP+TCP)\n", bindHost, dnsServer.Port)

	// Start API server
	api := dnsfilter.NewAPIServer(setup.Paths.DNSSocket, setup.Filter, server, setup.Loader, name)
	if err := api.Start(); err != nil {
		return fmt.Errorf("failed to start API server: %w", err)
	}
	defer api.Stop()
	fmt.Fprintf(os.Stderr, "API socket: %s\n", setup.Paths.DNSSocket)

	// Log mode
	mode := "active"
	if opts.Passive {
		mode = "passive"
	}
	fmt.Fprintf(os.Stderr, "Mode: %s\n", mode)
	fmt.Fprintf(os.Stderr, "DNS filter ready for instance %q\n", name)

	// Wait for signals or early startup failure
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
	case err := <-dnsServer.StartErr():
		return fmt.Errorf("DNS server failed after start: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nShutting down DNS filter...\n")
	return nil
}
