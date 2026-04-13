package factory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

const (
	// HelperPingTimeout is the timeout for pinging the privilege helper.
	HelperPingTimeout = 5 * time.Second

	// HelperStartTimeout is the maximum time to wait for the privilege helper to start (60s).
	HelperStartTimeout = 60 * time.Second

	// HelperShutdownTimeout is the timeout for graceful shutdown of the privilege helper.
	HelperShutdownTimeout = 2 * time.Second

	// HelperPollInterval is how often to check for the helper socket during startup.
	HelperPollInterval = 100 * time.Millisecond

	// EnvPrivilegeSocket is the environment variable for an external helper socket path.
	// When set, abox will connect to this socket instead of spawning a new helper.
	EnvPrivilegeSocket = "ABOX_PRIVILEGE_SOCKET"

	// EnvPrivilegeToken is the environment variable for the external helper auth token.
	// Required when EnvPrivilegeSocket is set.
	EnvPrivilegeToken = "ABOX_PRIVILEGE_TOKEN"
)

// Factory provides shared dependencies for all commands.
type Factory struct {
	// IO holds the standard I/O streams for the CLI session.
	IO *iostreams.IOStreams

	// ColorScheme provides terminal color helpers (auto-disabled for non-TTY).
	ColorScheme *cmdutil.ColorScheme

	// Prompter provides interactive prompt methods (nil in non-interactive contexts).
	Prompter cmdutil.Prompter

	// Config loads an instance configuration by name.
	Config func(name string) (*config.Instance, *config.Paths, error)

	mu               sync.Mutex
	dnsClients       map[string]*dnsfilter.Client // keyed by instance name
	httpClients      map[string]*httpClient       // keyed by instance name
	privilegeHelper  *PrivilegeHelper
	privilegeLogPath string                     // set by PrivilegeClientFor before helper starts
	backends         map[string]backend.Backend // cached backends by name
}

// httpClient wraps HTTP filter client connection
type httpClient struct {
	conn   *grpc.ClientConn
	client rpc.HTTPFilterClient
}

// Ensure sets *f to a new Factory if it is nil. This replaces the common
// pattern `if opts.Factory == nil { opts.Factory = factory.New() }`.
func Ensure(f **Factory) {
	if *f == nil {
		*f = New()
	}
}

// New creates a new Factory with default implementations.
func New() *Factory {
	io := iostreams.New()
	return &Factory{
		IO:          io,
		ColorScheme: cmdutil.NewColorScheme(io.IsTerminal()),
		Prompter:    cmdutil.NewLivePrompter(io),
		Config:      config.Load,
		dnsClients:  make(map[string]*dnsfilter.Client),
		httpClients: make(map[string]*httpClient),
		backends:    make(map[string]backend.Backend),
	}
}

// BackendFor returns the appropriate backend for an instance.
// For existing instances, it uses the backend recorded in the config.
// For new instances (config doesn't exist), it auto-detects the backend.
// The backend is cached for subsequent calls.
func (f *Factory) BackendFor(name string) (backend.Backend, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check cache first
	if b, ok := f.backends[name]; ok {
		return b, nil
	}

	// Try to load instance config
	inst, _, err := f.Config(name)
	if err == nil && inst.Backend != "" {
		// Instance exists with a recorded backend
		b, err := backend.Get(inst.Backend)
		if err != nil {
			return nil, fmt.Errorf("backend %q not available: %w", inst.Backend, err)
		}
		f.backends[name] = b
		return b, nil
	}

	// Instance doesn't exist or has no backend - auto-detect
	b, err := backend.AutoDetect()
	if err != nil {
		return nil, err
	}
	f.backends[name] = b
	return b, nil
}

// AutoDetectBackend returns the auto-detected backend for new instances.
// This is used when creating new instances to determine which backend to use.
func (f *Factory) AutoDetectBackend() (backend.Backend, error) {
	return backend.AutoDetect()
}

// ensureDNSConnection returns a cached DNS filter client connection,
// creating a new one if needed.
func (f *Factory) ensureDNSConnection(name string) (*dnsfilter.Client, error) {
	if client, ok := f.dnsClients[name]; ok {
		return client, nil
	}

	// Load config to get socket path
	_, paths, err := f.Config(name)
	if err != nil {
		return nil, err
	}

	// Check if socket exists (DNS filter running)
	if _, err := os.Stat(paths.DNSSocket); os.IsNotExist(err) {
		return nil, fmt.Errorf("DNS filter is not running for instance %q", name)
	}

	client, err := dnsfilter.Dial(paths.DNSSocket)
	if err != nil {
		return nil, err
	}

	f.dnsClients[name] = client
	return client, nil
}

// DNSClient returns a cached DNS filter client for the given instance name.
// Creates a new connection if one doesn't exist.
// Returns error if instance doesn't exist or DNS filter isn't running.
func (f *Factory) DNSClient(name string) (rpc.DNSFilterClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	client, err := f.ensureDNSConnection(name)
	if err != nil {
		return nil, err
	}
	return client.Client(), nil
}

// WithDNSClient creates a DNS client connection and executes the callback.
// The context is automatically cancelled when the callback returns.
func (f *Factory) WithDNSClient(name string, fn func(ctx context.Context, client rpc.DNSFilterClient) error) error {
	client, err := f.DNSClient(name)
	if err != nil {
		return fmt.Errorf("failed to connect to DNS filter: %w", err)
	}

	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	return fn(ctx, client)
}

// AllowlistClient returns a cached Allowlist client for the given instance name.
// The Allowlist service is provided by the DNS filter daemon.
func (f *Factory) AllowlistClient(name string) (rpc.AllowlistClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	client, err := f.ensureDNSConnection(name)
	if err != nil {
		return nil, err
	}
	return client.AllowlistClient(), nil
}

// WithAllowlistClient creates an Allowlist client connection and executes the callback.
// The context is automatically cancelled when the callback returns.
func (f *Factory) WithAllowlistClient(name string, fn func(ctx context.Context, client rpc.AllowlistClient) error) error {
	client, err := f.AllowlistClient(name)
	if err != nil {
		return fmt.Errorf("failed to connect to allowlist service: %w", err)
	}

	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	return fn(ctx, client)
}

// HTTPClient returns a cached HTTP filter client for the given instance name.
// Creates a new connection if one doesn't exist.
// Returns error if instance doesn't exist or HTTP filter isn't running.
func (f *Factory) HTTPClient(name string) (rpc.HTTPFilterClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if client, ok := f.httpClients[name]; ok {
		return client.client, nil
	}

	// Load config to get socket path
	_, paths, err := f.Config(name)
	if err != nil {
		return nil, err
	}

	// Check if socket exists (HTTP filter running)
	if _, err := os.Stat(paths.HTTPSocket); os.IsNotExist(err) {
		return nil, fmt.Errorf("HTTP filter is not running for instance %q", name)
	}

	conn, err := rpc.UnixDial(paths.HTTPSocket)
	if err != nil {
		return nil, err
	}

	client := &httpClient{
		conn:   conn,
		client: rpc.NewHTTPFilterClient(conn),
	}
	f.httpClients[name] = client
	return client.client, nil
}

// WithHTTPClient creates an HTTP filter client connection and executes the callback.
// The context is automatically cancelled when the callback returns.
func (f *Factory) WithHTTPClient(name string, fn func(ctx context.Context, client rpc.HTTPFilterClient) error) error {
	client, err := f.HTTPClient(name)
	if err != nil {
		return fmt.Errorf("failed to connect to HTTP filter: %w", err)
	}

	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	return fn(ctx, client)
}

// WithHTTPAllowlistClient creates an Allowlist client on the HTTP filter socket.
// The HTTP filter implements AllowlistServer for reload/add/remove/list operations.
func (f *Factory) WithHTTPAllowlistClient(name string, fn func(ctx context.Context, client rpc.AllowlistClient) error) error {
	_, paths, err := f.Config(name)
	if err != nil {
		return err
	}

	if _, err := os.Stat(paths.HTTPSocket); os.IsNotExist(err) {
		return fmt.Errorf("HTTP filter is not running for instance %q", name)
	}

	conn, err := rpc.UnixDial(paths.HTTPSocket)
	if err != nil {
		return fmt.Errorf("failed to connect to HTTP filter: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := rpc.NewAllowlistClient(conn)
	ctx, cancel := dnsfilter.ClientContext()
	defer cancel()

	return fn(ctx, client)
}

// PrivilegeClient returns the privilege helper client, starting helper if needed.
func (f *Factory) PrivilegeClient() (rpc.PrivilegeClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.privilegeHelper != nil && f.privilegeHelper.state == helperRunning {
		return f.privilegeHelper.client, nil
	}

	// Check for external helper via environment variables
	if socketPath := os.Getenv(EnvPrivilegeSocket); socketPath != "" {
		token := os.Getenv(EnvPrivilegeToken)
		if token == "" {
			return nil, fmt.Errorf("%s is set but %s is not", EnvPrivilegeSocket, EnvPrivilegeToken)
		}
		helper, err := connectExternalHelper(socketPath, token)
		if err != nil {
			return nil, err
		}
		f.privilegeHelper = helper
		return helper.client, nil
	}

	// Determine socket directory: prefer XDG_RUNTIME_DIR for security
	// XDG_RUNTIME_DIR is user-private (/run/user/<uid>), unlike /tmp which is world-writable
	socketDir := os.Getenv("XDG_RUNTIME_DIR")
	if socketDir == "" {
		socketDir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	// Refuse to continue if no secure runtime directory exists
	if _, err := os.Stat(socketDir); os.IsNotExist(err) { //nolint:gosec // checking directory existence, not opening untrusted path
		return nil, fmt.Errorf(
			"no secure runtime directory for privilege helper socket; "+
				"XDG_RUNTIME_DIR is unset and %s does not exist",
			socketDir)
	}

	// Generate random socket path to allow multiple concurrent abox instances
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random socket path: %w", err)
	}
	socketPath := fmt.Sprintf("%s/abox-privilege-%s.sock", socketDir, hex.EncodeToString(randomBytes))

	// Generate auth token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate auth token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	helper := &PrivilegeHelper{
		socketPath: socketPath,
		token:      token,
		logPath:    f.privilegeLogPath,
		errOut:     f.IO.ErrOut,
	}
	if err := helper.start(); err != nil {
		return nil, err
	}

	f.privilegeHelper = helper
	return helper.client, nil
}

// PrivilegeClientFor returns a privilege client, logging to the instance's log file.
// On first call, the helper is started with logging to the given instance.
// Subsequent calls reuse the existing helper (log path from first call).
func (f *Factory) PrivilegeClientFor(name string) (rpc.PrivilegeClient, error) {
	// Get instance paths (works for existing or new instances)
	paths, err := config.GetPaths(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get paths for %q: %w", name, err)
	}

	f.mu.Lock()
	if f.privilegeLogPath == "" {
		f.privilegeLogPath = paths.PrivilegeHelperLog
	}
	f.mu.Unlock()

	return f.PrivilegeClient()
}

// Close closes all cached clients and should be called on shutdown.
func (f *Factory) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, client := range f.dnsClients {
		_ = client.Close()
	}
	f.dnsClients = make(map[string]*dnsfilter.Client)

	for _, client := range f.httpClients {
		_ = client.conn.Close()
	}
	f.httpClients = make(map[string]*httpClient)

	if f.privilegeHelper != nil {
		f.privilegeHelper.Shutdown()
		f.privilegeHelper = nil
	}
}
