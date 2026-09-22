package serve

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/secretstore"
	"github.com/sandialabs/abox/internal/validation"
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

	// Apply the connection cap from config. 0/unset keeps NewServer's default.
	if n := setup.Inst.HTTP.MaxConnections; n > 0 {
		server.SetMaxConns(n)
	}

	// Apply the opt-in private-target allow-list (SSRF policy). An invalid CIDR
	// must fail closed rather than silently reverting to deny-all, so surface it.
	if err := server.SetAllowPrivateTargets(setup.Inst.HTTP.AllowPrivateTargets); err != nil {
		return fmt.Errorf("invalid http.allow_private_targets: %w", err)
	}

	// Load CA certificate for TLS MITM if enabled
	if setup.Inst.HTTP.MITM {
		if err := server.LoadCA(setup.Paths.CACert, setup.Paths.CAKey); err != nil {
			return fmt.Errorf("failed to load CA certificate: %w (run 'abox remove %s && abox create %s' to regenerate)", err, name, name)
		}
		fmt.Fprintf(os.Stderr, "TLS MITM enabled (domain fronting protection)\n")
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: TLS MITM disabled - domain fronting protection unavailable\n")
	}

	// Apply secret injections after the MITM CA is loaded so that the CA is ready
	// before any request can be intercepted (avoids an inject-less window).
	if err := applySecretInjections(server, setup, opts.Passive, name); err != nil {
		return err
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

	// Start HTTP server on the platform's proxy bind address (the gateway IP on
	// Linux; the wildcard on macOS, where the vmnet bridge does not exist yet).
	bindHost := filterbase.HTTPListenAddress(setup.Inst.Gateway)
	listenAddr := fmt.Sprintf("%s:%d", bindHost, setup.Inst.HTTP.Port)

	if err := server.Start(listenAddr); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}
	defer func() {
		ctx, cancel := httpfilter.ClientContext()
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	fmt.Fprintf(os.Stderr, "HTTP proxy listening on %s:%d\n", bindHost, server.GetListenPort())

	// Start API server
	api := httpfilter.NewAPIServer(setup.Paths.HTTPSocket, setup.Filter, server, setup.Loader, name)
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

// applySecretInjections translates the instance's configured secret-injection
// bindings into resolved httpfilter rules and installs them. It reads secret
// values from the per-instance host store; a binding whose key has no stored
// value becomes a strip rule so the guest can never supply its own credential to
// a bound host.
//
// It fails closed: injections require TLS MITM (there is no request to modify in
// tunnel mode) and are refused in passive mode (which forwards everything and
// would transmit live credentials during profiling).
func applySecretInjections(server *httpfilter.Server, setup *filterbase.DaemonSetup, passive bool, name string) error {
	bindings := setup.Inst.HTTP.SecretInjections
	if len(bindings) == 0 {
		return nil
	}
	if !setup.Inst.HTTP.MITM {
		return fmt.Errorf("http.secret_injections require TLS MITM, but http.mitm is disabled for instance %q", name)
	}
	if passive {
		return fmt.Errorf("http.secret_injections cannot be used in passive mode for instance %q (would transmit credentials while profiling)", name)
	}

	// An upstream proxy (http_proxy/https_proxy) resolves the target itself, so the
	// dial-time SSRF/rebinding gate can't vet where an injected-secret request
	// actually lands. The origin's TLS cert still pins the secret to the bound
	// host, but warn the operator that containment is weaker in this configuration.
	for _, ev := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(ev) != "" {
			logging.Warn("secret injection with an upstream proxy configured: SSRF containment is weaker for the proxied leg",
				"instance", name, "env", ev)
			break
		}
	}

	values, err := secretstore.New(setup.Paths.Secrets).Load()
	if err != nil {
		return fmt.Errorf("failed to load secret store: %w", err)
	}

	rules := resolveSecretRules(name, bindings, values)
	server.SetSecretInjections(name, rules)
	fmt.Fprintf(os.Stderr, "Secret injection configured for %d binding(s)\n", len(rules))
	return nil
}

// resolveSecretRules translates config bindings + stored values into resolved
// httpfilter rules. A binding whose key has no stored value, or whose resolved
// value is not a valid header value (e.g. an embedded newline that could break the
// request or enable smuggling), degrades to a strip rule so the guest can never
// supply its own credential to the bound host. This is a pure function so the
// fail-closed resolution is unit-testable.
func resolveSecretRules(name string, bindings []config.SecretInjection, values map[string]string) []httpfilter.SecretRule {
	stripRule := func(b config.SecretInjection) httpfilter.SecretRule {
		return httpfilter.SecretRule{Key: b.Key, Host: b.Host, Header: b.Header, PathPrefix: b.PathPrefix, Strip: true}
	}
	rules := make([]httpfilter.SecretRule, 0, len(bindings))
	for _, b := range bindings {
		val, ok := values[b.Key]
		if !ok {
			logging.Warn("secret injection key has no stored value; stripping header instead",
				"instance", name, "key", b.Key, "host", b.Host, "header", b.Header)
			rules = append(rules, stripRule(b))
			continue
		}
		value := b.ValuePrefix + val
		if err := validation.ValidateHTTPHeaderValue(value); err != nil {
			logging.Warn("secret value is not a valid header value; stripping header instead",
				"instance", name, "key", b.Key, "host", b.Host, "header", b.Header, "error", err)
			rules = append(rules, stripRule(b))
			continue
		}
		rules = append(rules, httpfilter.SecretRule{
			Key:        b.Key,
			Host:       b.Host,
			Header:     b.Header,
			Value:      value,
			PathPrefix: b.PathPrefix,
		})
	}
	return rules
}
