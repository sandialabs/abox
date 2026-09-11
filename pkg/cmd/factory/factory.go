package factory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/internal/logging"
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

	// EnvBackend explicitly selects a VM backend by name (e.g. "vmware"),
	// bypassing auto-detection. Required to select an experimental backend, which
	// auto-detection never chooses silently.
	EnvBackend = "ABOX_BACKEND"
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

	mu                     sync.Mutex
	dnsClients             map[string]*dnsfilter.Client // keyed by instance name
	httpClients            map[string]*httpClient       // keyed by instance name
	privilegeHelper        *PrivilegeHelper
	privilegeLogPath       string                     // set by EgressClientFor before helper starts
	backends               map[string]backend.Backend // cached backends by name
	noInteractivePrivilege bool                       // when true, never launch an interactive sudo/pkexec prompt
}

// SetNonInteractivePrivilege controls whether acquiring the privileged helper may
// launch an interactive sudo/pkexec prompt. Teardown/diagnostic commands (stop,
// doctor on a non-TTY) set this so they never block on a password: if only an
// interactive escalation path is available, privilege acquisition fails and the
// caller treats the host-side step as best-effort. The setuid helper, an
// already-running helper, an external helper (ABOX_PRIVILEGE_SOCKET), and running
// as root are all non-interactive and remain available.
func (f *Factory) SetNonInteractivePrivilege(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noInteractivePrivilege = v
}

// SetNonInteractivePrivilegeFromTTY enables non-interactive privilege acquisition
// when there is no controlling terminal to prompt on (stdout is not a TTY, e.g.
// CI/scripts/pipes), and leaves interactive escalation available otherwise. This
// is the shared "no TTY to type a password on" decision used by the diagnostic
// and teardown-from-TTY commands (doctor, down); a command that must ALWAYS be
// best-effort regardless of TTY (stop) sets the flag unconditionally instead.
func (f *Factory) SetNonInteractivePrivilegeFromTTY() {
	if !f.IO.IsTerminal() {
		f.SetNonInteractivePrivilege(true)
	}
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
		warnIfExperimental(b.Name())
		f.injectEgressProvider(b, name)
		f.injectPfProvider(b, name)
		f.injectStorageProvider(b, name)
		f.backends[name] = b
		return b, nil
	}

	// Instance doesn't exist or has no backend - resolve (explicit ABOX_BACKEND or
	// auto-detect).
	b, err := resolveBackend()
	if err != nil {
		return nil, err
	}
	f.injectEgressProvider(b, name)
	f.injectPfProvider(b, name)
	f.injectStorageProvider(b, name)
	f.backends[name] = b
	return b, nil
}

// resolveBackend selects the backend to use: the one named by ABOX_BACKEND when
// set (the only way to reach an experimental backend), otherwise auto-detection
// (which never selects an experimental backend silently). A warning is emitted
// when the resolved backend is experimental.
func resolveBackend() (backend.Backend, error) {
	if name := os.Getenv(EnvBackend); name != "" {
		b, err := backend.Get(name)
		if err != nil {
			return nil, fmt.Errorf("backend %q (from %s) not available: %w", name, EnvBackend, err)
		}
		warnIfExperimental(b.Name())
		return b, nil
	}
	return backend.AutoDetect()
}

// warnIfExperimental emits a one-line warning when an experimental backend is in
// use, so the unvalidated-on-real-hardware status is visible at the point of use.
func warnIfExperimental(name string) {
	if backend.IsExperimental(name) {
		logging.Warn("using experimental backend; not validated on real hardware",
			"backend", name)
	}
}

// injectEgressProvider wires the privileged egress enforcer provider into a
// backend that supports it (backend.EgressProviderSetter), so its
// EgressController can install host-side rules (iptables DNS REDIRECT + INPUT
// accepts) on demand. The provider is a closure invoked lazily, only when
// enforcement is actually needed (Define/Remove), so read-only paths never
// trigger privilege escalation. Passing a non-empty name routes helper logs to
// that instance's log file; an empty name (auto-detected, instance-less
// backends) uses the default helper log.
func (f *Factory) injectEgressProvider(b backend.Backend, name string) {
	setter, ok := b.(backend.EgressProviderSetter)
	if !ok {
		return
	}
	setter.SetEgressProvider(func() (backend.EgressEnforcer, error) {
		var (
			c   rpc.EgressClient
			err error
		)
		if name != "" {
			c, err = f.EgressClientFor(name)
		} else {
			c, err = f.EgressClient()
		}
		if err != nil {
			return nil, err
		}
		return firewall.NewEgressEnforcer(c), nil
	})
}

// injectPfProvider wires the privileged pfctl provider into a backend that
// supports it (backend.PfProviderSetter), so its EgressController can enable pf
// and load per-instance anchors on demand. Parallel to injectEgressProvider: the
// provider is a closure invoked lazily (only when enforcement is needed), so
// read-only paths never trigger privilege escalation. A backend implements at
// most one of the two setters, so calling both injectors is safe — the
// non-matching one early-returns.
func (f *Factory) injectPfProvider(b backend.Backend, name string) {
	setter, ok := b.(backend.PfProviderSetter)
	if !ok {
		return
	}
	setter.SetPfProvider(func() (backend.PfEnforcer, error) {
		c, err := f.PfClientFor(name)
		if err != nil {
			return nil, err
		}
		return firewall.NewPfClient(c), nil
	})
}

// injectStorageProvider wires the privileged storage enforcer provider into a
// backend that supports it (backend.StorageProviderSetter), so its disk manager
// can provision the per-user storage root on demand. Parallel to
// injectEgressProvider (and sharing the same Egress helper client): the provider
// is a closure invoked lazily, only when a disk op actually needs the root
// prepared (create/import), so read-only paths never trigger privilege
// escalation.
func (f *Factory) injectStorageProvider(b backend.Backend, name string) {
	setter, ok := b.(backend.StorageProviderSetter)
	if !ok {
		return
	}
	setter.SetStorageProvider(func() (backend.StorageEnforcer, error) {
		var (
			c   rpc.EgressClient
			err error
		)
		if name != "" {
			c, err = f.EgressClientFor(name)
		} else {
			c, err = f.EgressClient()
		}
		if err != nil {
			return nil, err
		}
		return firewall.NewStorageEnforcer(c), nil
	})
}

// AutoDetectBackend returns the backend for new instances: the one selected by
// ABOX_BACKEND when set, otherwise the auto-detected one (auto-detection never
// selects an experimental backend). The egress enforcer provider is injected
// (instance-less) so the returned backend is safe to use for egress operations
// should a caller need to.
func (f *Factory) AutoDetectBackend() (backend.Backend, error) {
	b, err := resolveBackend()
	if err != nil {
		return nil, err
	}
	f.injectEgressProvider(b, "")
	f.injectPfProvider(b, "")
	f.injectStorageProvider(b, "")
	return b, nil
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

// EgressClient returns the privileged egress helper client, starting the helper if needed.
func (f *Factory) EgressClient() (rpc.EgressClient, error) {
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

	// Determine socket directory via the platform's secure runtime dir seam.
	// On linux this is XDG_RUNTIME_DIR or /run/user/<uid>; on darwin it is
	// $TMPDIR. The seam asserts the directory exists, is owned by the invoking
	// user, and is not group/other-writable (refusing a world-writable /tmp),
	// so the helper socket cannot be pre-created or hijacked by another user.
	socketDir, err := config.SecureRuntimeDir()
	if err != nil {
		return nil, fmt.Errorf("no secure runtime directory for privilege helper socket: %w", err)
	}

	// Generate random socket path to allow multiple concurrent abox instances
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random socket path: %w", err)
	}
	// filepath.Join (not Sprintf) so the path stays clean even if socketDir ever
	// carries a trailing separator; the helper rejects a non-clean --socket.
	socketPath := filepath.Join(socketDir, fmt.Sprintf("abox-privilege-%s.sock", hex.EncodeToString(randomBytes)))

	// Generate auth token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate auth token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	helper := &PrivilegeHelper{
		socketPath:    socketPath,
		token:         token,
		logPath:       f.privilegeLogPath,
		errOut:        f.IO.ErrOut,
		noInteractive: f.noInteractivePrivilege,
	}
	if err := helper.start(); err != nil {
		return nil, err
	}

	f.privilegeHelper = helper
	return helper.client, nil
}

// EgressClientFor returns a privileged egress client, logging to the instance's log file.
// On first call, the helper is started with logging to the given instance.
// Subsequent calls reuse the existing helper (log path from first call).
func (f *Factory) EgressClientFor(name string) (rpc.EgressClient, error) {
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

	return f.EgressClient()
}

// PfClientFor returns a token-wrapped privileged pfctl client for the macOS
// egress controller, spawning/reusing the SAME privilege helper as EgressClientFor
// (on darwin the helper registers the Pf service). It differs from EgressClientFor
// only in the client constructor: it wraps the shared helper connection with
// NewPfClientWithToken (every Pf method, including Ping, requires the auth token).
func (f *Factory) PfClientFor(name string) (rpc.PfClient, error) {
	// Reuse the helper-spawn/connection machinery: EgressClientFor ensures the
	// helper is started (routing its logs to this instance) and cached in
	// f.privilegeHelper. We then build a Pf client over the SAME connection.
	if _, err := f.EgressClientFor(name); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.privilegeHelper == nil || f.privilegeHelper.conn == nil {
		return nil, errors.New("privilege helper connection unavailable for pf client")
	}
	return rpc.NewPfClientWithToken(f.privilegeHelper.conn, f.privilegeHelper.token), nil
}

// StorageEnforcerFor returns a privileged storage enforcer for provisioning the
// caller's per-user disk storage root, routing helper logs to the named
// instance. It reuses the SAME Egress helper client as the disk manager's
// injected provider (the storage-root step shares the single privilege helper);
// `abox migrate` uses it to provision + regroup the root after relocating files.
func (f *Factory) StorageEnforcerFor(name string) (backend.StorageEnforcer, error) {
	c, err := f.EgressClientFor(name)
	if err != nil {
		return nil, err
	}
	return firewall.NewStorageEnforcer(c), nil
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
