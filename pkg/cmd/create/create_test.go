package create

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// newTestFactory builds a Factory wired to test IO streams. The returned buffer
// receiver captures stdout so tests can assert on emitted output.
func newTestFactory(t *testing.T) *factory.Factory {
	t.Helper()
	ios, _, _, _ := iostreams.Test()
	return &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
		Config:      config.Load,
	}
}

// registerMockBackend installs a mock backend under the given name and selects it
// via ABOX_BACKEND so create's opts.Factory.AutoDetectBackend() resolves to it
// without touching a real hypervisor. The registry is reset in t.Cleanup. The
// backend's StorageDir is pointed at a temp dir so any disk-path computation
// stays hermetic. The returned *mock.Backend can have its Func hooks customized
// before the create flow runs.
func registerMockBackend(t *testing.T, name string, be *mock.Backend) {
	t.Helper()
	backend.ResetForTesting()
	t.Cleanup(backend.ResetForTesting)

	if be.NameFunc == nil {
		be.NameFunc = func() string { return name }
	}
	if be.StorageDirFunc == nil {
		storage := t.TempDir()
		be.StorageDirFunc = func() string { return storage }
	}

	backend.Register(name, 10, func() backend.Backend { return be })
	t.Setenv(factory.EnvBackend, name)
}

// isolateDataHome points the abox data directory (config, locks, allowlist, SSH
// keys) at a temp dir so create writes nothing to the developer's real HOME.
func isolateDataHome(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
}

// TestRunCreate_DryRunSelectsMockBackend drives the create flow in --dry-run mode
// through the mock backend. It asserts the backend was selected (its DryRun hook
// fires) and that no error is returned, exercising the backend-selection seam
// without any real hypervisor.
func TestRunCreate_DryRunSelectsMockBackend(t *testing.T) {
	isolateDataHome(t)

	var dryRunCalled bool
	var gotName string
	be := &mock.Backend{
		DryRunFunc: func(inst *config.Instance, _ *config.Paths, _ io.Writer, _ backend.VMCreateOptions) error {
			dryRunCalled = true
			gotName = inst.Name
			return nil
		},
	}
	registerMockBackend(t, "mock", be)

	f := newTestFactory(t)
	opts := &Options{
		Factory: f,
		CPUs:    2,
		Memory:  4096,
		Base:    "ubuntu-24.04",
		Disk:    "20G",
		DryRun:  true,
	}

	if err := Run(context.Background(), opts, "dryvm"); err != nil {
		t.Fatalf("Run(dry-run) error = %v", err)
	}
	if !dryRunCalled {
		t.Fatal("expected the mock backend's DryRun to be called")
	}
	if gotName != "dryvm" {
		t.Errorf("DryRun instance name = %q, want %q", gotName, "dryvm")
	}
}

// TestRunCreate_FullFlowThroughMock drives a complete (non-dry-run) create through
// the mock backend and reads back the persisted config. This verifies the
// end-to-end wiring: backend selection, subnet/gateway allocation via
// ResolveNetwork, and population of the instance config (Backend name, Subnet,
// Gateway, Bridge from ResourceNames, MAC, derived IP). All network/disk/VM ops
// are mock no-ops; only ssh-keygen shells out (host binary, no root).
func TestRunCreate_FullFlowThroughMock(t *testing.T) {
	isolateDataHome(t)
	registerMockBackend(t, "mock", &mock.Backend{})

	f := newTestFactory(t)
	opts := &Options{
		Factory: f,
		CPUs:    2,
		Memory:  4096,
		Base:    "ubuntu-24.04",
		Disk:    "20G",
		NoMITM:  true, // skip CA cert generation to keep the flow minimal
		Brief:   true,
	}

	if err := Run(context.Background(), opts, "fullvm"); err != nil {
		t.Fatalf("Run(full) error = %v", err)
	}

	inst, _, err := config.Load("fullvm")
	if err != nil {
		t.Fatalf("config.Load after create: %v", err)
	}
	if inst.Backend != "mock" {
		t.Errorf("inst.Backend = %q, want %q", inst.Backend, "mock")
	}
	// ResolveNetwork falls back to the shared allocator (mock is not a
	// NetworkDefaulter): expect a populated subnet and gateway.
	if inst.Subnet == "" {
		t.Error("inst.Subnet is empty; ResolveNetwork should have allocated one")
	}
	if inst.Gateway == "" {
		t.Error("inst.Gateway is empty; ResolveNetwork should have derived one")
	}
	// Bridge comes from the backend's ResourceNames(name).Network.
	if want := "mock-fullvm"; inst.Bridge != want {
		t.Errorf("inst.Bridge = %q, want %q", inst.Bridge, want)
	}
	if inst.MACAddress == "" {
		t.Error("inst.MACAddress is empty; backend.GenerateMAC should have set it")
	}
	if inst.IPAddress == "" {
		t.Error("inst.IPAddress is empty; DeriveHostIP(gateway) should have set it")
	}
}

// TestRunCreate_HonorsRequestedSubnet asserts that a requested --subnet is passed
// through ResolveNetwork verbatim and persisted on the instance, with the gateway
// derived from it.
func TestRunCreate_HonorsRequestedSubnet(t *testing.T) {
	isolateDataHome(t)
	registerMockBackend(t, "mock", &mock.Backend{})

	f := newTestFactory(t)
	const wantSubnet = "192.168.77.0/24"
	opts := &Options{
		Factory: f,
		CPUs:    2,
		Memory:  4096,
		Base:    "ubuntu-24.04",
		Disk:    "20G",
		Subnet:  wantSubnet,
		NoMITM:  true,
		Brief:   true,
	}

	if err := Run(context.Background(), opts, "netvm"); err != nil {
		t.Fatalf("Run(subnet) error = %v", err)
	}

	inst, _, err := config.Load("netvm")
	if err != nil {
		t.Fatalf("config.Load after create: %v", err)
	}
	if inst.Subnet != wantSubnet {
		t.Errorf("inst.Subnet = %q, want %q (requested subnet honored verbatim)", inst.Subnet, wantSubnet)
	}
	if inst.Gateway != "192.168.77.1" {
		t.Errorf("inst.Gateway = %q, want %q (derived from requested subnet)", inst.Gateway, "192.168.77.1")
	}
}

// TestAllocateSubnet_NetworkDefaulter asserts that allocateSubnet routes through
// the backend's NetworkDefaulter hook when the backend implements it and no
// explicit subnet is requested.
func TestAllocateSubnet_NetworkDefaulter(t *testing.T) {
	be := defaulterBackend{
		Backend: &mock.Backend{},
		subnet:  "192.168.130.0/24",
		gateway: "192.168.130.1",
	}
	opts := &Options{}

	subnet, gateway, err := allocateSubnet(opts, be)
	if err != nil {
		t.Fatalf("allocateSubnet error = %v", err)
	}
	if subnet != "192.168.130.0/24" || gateway != "192.168.130.1" {
		t.Errorf("got subnet=%q gateway=%q, want the defaulter's values", subnet, gateway)
	}
}

// TestAllocateSubnet_InvalidRequested asserts allocateSubnet surfaces a clear
// "invalid subnet" error when a bad --subnet is requested.
func TestAllocateSubnet_InvalidRequested(t *testing.T) {
	opts := &Options{Subnet: "not-a-cidr"}
	_, _, err := allocateSubnet(opts, &mock.Backend{})
	if err == nil {
		t.Fatal("allocateSubnet expected error for invalid --subnet, got nil")
	}
	if !strings.Contains(err.Error(), "invalid subnet") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "invalid subnet")
	}
}

// TestRunCreate_MonitorRejectedWhenNoTransport asserts the fail-fast guard: a
// backend whose MonitorTransport() is nil combined with --monitor must error out
// early (before any resources are created) with a clear message naming the
// backend.
func TestRunCreate_MonitorRejectedWhenNoTransport(t *testing.T) {
	isolateDataHome(t)

	var dryRunCalled bool
	be := &mock.Backend{
		// No monitor transport (mimics vfkit on macOS).
		MonitorTransportFunc: func() backend.MonitorTransport { return nil },
		DryRunFunc: func(_ *config.Instance, _ *config.Paths, _ io.Writer, _ backend.VMCreateOptions) error {
			dryRunCalled = true
			return nil
		},
	}
	registerMockBackend(t, "notransport", be)

	f := newTestFactory(t)
	opts := &Options{
		Factory:        f,
		CPUs:           2,
		Memory:         4096,
		Base:           "ubuntu-24.04",
		Disk:           "20G",
		MonitorEnabled: true,
		DryRun:         true, // guard runs before dry-run; DryRun must NOT fire
	}

	err := Run(context.Background(), opts, "monvm")
	if err == nil {
		t.Fatal("expected an error when monitor is enabled on a backend with no monitor transport")
	}
	if !strings.Contains(err.Error(), "does not support security monitoring") {
		t.Errorf("error = %q, want it to explain the backend lacks monitoring support", err.Error())
	}
	if !strings.Contains(err.Error(), "notransport") {
		t.Errorf("error = %q, want it to name the backend", err.Error())
	}
	if dryRunCalled {
		t.Error("DryRun should not run: the monitor-transport guard must fail fast first")
	}
}

// TestRunCreate_MonitorAllowedWithTransport is the positive counterpart: with a
// backend that DOES provide a monitor transport, --monitor passes the guard and
// the create (dry-run) succeeds.
func TestRunCreate_MonitorAllowedWithTransport(t *testing.T) {
	isolateDataHome(t)
	withMonitorGuestArch(t, "amd64")

	var dryRunCalled bool
	be := &mock.Backend{
		// Default MonitorTransport (non-nil) is used since we leave the hook unset.
		DryRunFunc: func(_ *config.Instance, _ *config.Paths, _ io.Writer, _ backend.VMCreateOptions) error {
			dryRunCalled = true
			return nil
		},
	}
	registerMockBackend(t, "withtransport", be)

	f := newTestFactory(t)
	opts := &Options{
		Factory:        f,
		CPUs:           2,
		Memory:         4096,
		Base:           "ubuntu-24.04",
		Disk:           "20G",
		MonitorEnabled: true,
		DryRun:         true,
	}

	if err := Run(context.Background(), opts, "monokvm"); err != nil {
		t.Fatalf("Run(monitor+transport) error = %v", err)
	}
	if !dryRunCalled {
		t.Fatal("expected DryRun to run once the monitor guard passes")
	}
}

// withMonitorGuestArch overrides the arch used by the monitor gate for the
// duration of a test, so the amd64-only restriction is exercisable on any host.
func withMonitorGuestArch(t *testing.T, arch string) {
	t.Helper()
	prev := monitorGuestArch
	monitorGuestArch = arch
	t.Cleanup(func() { monitorGuestArch = prev })
}

// TestRunCreate_MonitorRejectedOnNonAmd64 asserts monitoring fails fast on a
// non-amd64 guest even when the backend provides a transport: the Tetragon
// install path is amd64-only, so we must not boot a guest whose opted-in monitor
// would silently never run.
func TestRunCreate_MonitorRejectedOnNonAmd64(t *testing.T) {
	isolateDataHome(t)
	withMonitorGuestArch(t, "arm64")

	var dryRunCalled bool
	be := &mock.Backend{
		// Non-nil transport: the arch gate must reject independently of transport.
		DryRunFunc: func(_ *config.Instance, _ *config.Paths, _ io.Writer, _ backend.VMCreateOptions) error {
			dryRunCalled = true
			return nil
		},
	}
	registerMockBackend(t, "arm64backend", be)

	f := newTestFactory(t)
	opts := &Options{
		Factory:        f,
		CPUs:           2,
		Memory:         4096,
		Base:           "ubuntu-24.04",
		Disk:           "20G",
		MonitorEnabled: true,
		DryRun:         true,
	}

	err := Run(context.Background(), opts, "armmonvm")
	if err == nil {
		t.Fatal("expected an error when monitor is enabled on a non-amd64 guest")
	}
	if !strings.Contains(err.Error(), "amd64") {
		t.Errorf("error = %q, want it to explain monitoring requires amd64", err.Error())
	}
	if dryRunCalled {
		t.Error("DryRun should not run: the arch guard must fail fast first")
	}
}

// defaulterBackend embeds mock.Backend and implements backend.NetworkDefaulter so
// allocateSubnet's per-backend allocation path is exercised.
type defaulterBackend struct {
	*mock.Backend
	subnet, gateway string
	err             error
}

func (d defaulterBackend) NetworkDefaults() (string, string, error) {
	return d.subnet, d.gateway, d.err
}

func TestNewCmdCreate_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdCreate(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--cpus", "4", "--memory", "8192", "--base", "ubuntu-24.04", "--dry-run", "myvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if gotOpts.CPUs != 4 {
		t.Errorf("CPUs = %d, want 4", gotOpts.CPUs)
	}
	if gotOpts.Memory != 8192 {
		t.Errorf("Memory = %d, want 8192", gotOpts.Memory)
	}
	if gotOpts.Base != "ubuntu-24.04" {
		t.Errorf("Base = %q, want %q", gotOpts.Base, "ubuntu-24.04")
	}
	if !gotOpts.DryRun {
		t.Error("expected DryRun to be true")
	}
	if gotOpts.Name != "myvm" {
		t.Errorf("Name = %q, want %q", gotOpts.Name, "myvm")
	}
}

func TestValidateCreateInputs_Upstream(t *testing.T) {
	tests := []struct {
		name         string
		upstream     string
		wantErr      bool
		wantUpstream string
	}{
		// Empty means "use the host's system resolver"; accepted without
		// normalization and left empty so config.yaml persists "" (regression
		// guard: NormalizeUpstreamDNS("") errors, so create must skip it).
		{"empty-accepted", "", false, ""},
		{"explicit-normalized", "1.1.1.1", false, "1.1.1.1:53"},
		{"invalid-rejected", "1.1.1.1:0", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{
				CPUs:     2,
				Memory:   4096,
				Disk:     "20G",
				Upstream: tt.upstream,
			}
			err := validateCreateInputs(opts, "myvm")
			if tt.wantErr {
				if err == nil {
					t.Fatal("validateCreateInputs() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateCreateInputs() error = %v", err)
			}
			if opts.Upstream != tt.wantUpstream {
				t.Errorf("opts.Upstream = %q, want %q", opts.Upstream, tt.wantUpstream)
			}
		})
	}
}

func TestNewCmdCreate_RequiresName(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdCreate(f, func(o *Options) error {
		t.Fatal("runF should not be called when name is missing")
		return nil
	})
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no name and no --from-file is provided")
	}
}

// writeBoxfile writes an abox.yaml into a fresh temp dir and returns its path.
func writeBoxfile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "abox.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write abox.yaml: %v", err)
	}
	return path
}

// boxfileWithHTTPKeys is an abox.yaml exercising every key that one of the two
// former mapping sites used to drop.
const boxfileWithHTTPKeys = `version: 1
name: %s
cpus: 2
memory: 4096
disk: 20G
base: ubuntu-24.04
allowlist:
  - allowed.example.com
  - second.example.com
http:
  max_connections: 1024
  mitm_exceptions:
    - pinned.example.com
  secret_injections:
    - key: token
      host: api.example.com
      header: x-api-key
monitor:
  kprobe_multi: true
`

// assertDroppedKeysPersisted checks the abox.yaml keys that used to be silently
// dropped actually reached the instance config and allowlist file.
func assertDroppedKeysPersisted(t *testing.T, name string) {
	t.Helper()
	inst, paths, err := config.Load(name)
	if err != nil {
		t.Fatalf("config.Load after create: %v", err)
	}

	if got := inst.HTTP.MITMExceptions; len(got) != 1 || got[0] != "pinned.example.com" {
		t.Errorf("inst.HTTP.MITMExceptions = %v, want [pinned.example.com]", got)
	}
	if got := inst.HTTP.SecretInjections; len(got) != 1 || got[0].Host != "api.example.com" {
		t.Errorf("inst.HTTP.SecretInjections = %v, want one binding for api.example.com", got)
	}
	if inst.HTTP.MaxConnections != 1024 {
		t.Errorf("inst.HTTP.MaxConnections = %d, want 1024", inst.HTTP.MaxConnections)
	}
	if !inst.Monitor.KprobeMulti {
		t.Error("inst.Monitor.KprobeMulti = false, want true")
	}

	data, err := os.ReadFile(paths.Allowlist)
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	for _, domain := range []string{"allowed.example.com", "second.example.com"} {
		if !strings.Contains(string(data), domain) {
			t.Errorf("allowlist file missing %q from abox.yaml; got:\n%s", domain, data)
		}
	}
}

// TestRunCreate_FromFileHonorsBoxfileKeys covers `abox create --from-file`,
// which used to drop allowlist: entirely (writing the deny-everything default
// instead) because loadFromBoxfile never assigned opts.Allowlist.
func TestRunCreate_FromFileHonorsBoxfileKeys(t *testing.T) {
	isolateDataHome(t)
	registerMockBackend(t, "mock", &mock.Backend{})

	path := writeBoxfile(t, fmt.Sprintf(boxfileWithHTTPKeys, "fromfile"))
	opts := &Options{Factory: newTestFactory(t), FromFile: path, Brief: true}

	if err := Run(context.Background(), opts, ""); err != nil {
		t.Fatalf("Run(--from-file) error = %v", err)
	}
	assertDroppedKeysPersisted(t, "fromfile")
}

// TestRunFromBoxfile_HonorsBoxfileKeys covers the `abox up` path, which used to
// hand-build create.Options and silently dropped http.secret_injections,
// http.mitm_exceptions, http.max_connections and monitor.kprobe_multi.
func TestRunFromBoxfile_HonorsBoxfileKeys(t *testing.T) {
	isolateDataHome(t)
	registerMockBackend(t, "mock", &mock.Backend{})

	path := writeBoxfile(t, fmt.Sprintf(boxfileWithHTTPKeys, "fromboxfile"))
	box, boxDir, err := boxfile.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if err := RunFromBoxfile(context.Background(), newTestFactory(t), box, boxDir, true); err != nil {
		t.Fatalf("RunFromBoxfile() error = %v", err)
	}
	assertDroppedKeysPersisted(t, "fromboxfile")
}

// TestRunCreate_BoxfileBeatsNoMITM pins the --from-file precedence rule: the
// file wins over CLI flags for every option, --no-mitm included. The NoMITM
// inversion therefore has to stay above applyBoxfile in Run. Changing this is a
// deliberate semantic change to --from-file, not a refactor side effect.
func TestRunCreate_BoxfileBeatsNoMITM(t *testing.T) {
	isolateDataHome(t)
	registerMockBackend(t, "mock", &mock.Backend{})

	path := writeBoxfile(t, "version: 1\nname: mitmfile\ncpus: 2\nmemory: 4096\nhttp:\n  mitm: true\n")
	opts := &Options{Factory: newTestFactory(t), FromFile: path, NoMITM: true, Brief: true}

	if err := Run(context.Background(), opts, ""); err != nil {
		t.Fatalf("Run(--from-file --no-mitm) error = %v", err)
	}

	inst, _, err := config.Load("mitmfile")
	if err != nil {
		t.Fatalf("config.Load after create: %v", err)
	}
	if !inst.HTTP.MITM {
		t.Error("inst.HTTP.MITM = false; the boxfile's mitm: true must win over --no-mitm")
	}
}

// TestApplyBoxfile_ClaudeExample guards the shipped example whose documented
// `abox up` workflow silently produced an instance with no credential
// injection, defeating the feature the example exists to demonstrate.
func TestApplyBoxfile_ClaudeExample(t *testing.T) {
	box, boxDir, err := boxfile.LoadFile(filepath.Join("..", "..", "..", "examples", "claude", "abox.yaml"))
	if err != nil {
		t.Fatalf("LoadFile(examples/claude): %v", err)
	}

	var opts Options
	if err := applyBoxfile(&opts, box, boxDir); err != nil {
		t.Fatalf("applyBoxfile() error = %v", err)
	}

	if len(opts.SecretInjections) != 1 {
		t.Fatalf("SecretInjections = %v, want the api.anthropic.com binding", opts.SecretInjections)
	}
	if got := opts.SecretInjections[0]; got.Host != "api.anthropic.com" || got.Header != "x-api-key" {
		t.Errorf("SecretInjections[0] = %+v, want host api.anthropic.com header x-api-key", got)
	}
	if len(opts.Allowlist) == 0 {
		t.Error("Allowlist is empty; the example declares two domains")
	}
}

// TestRunCreate_HonorsBoxfileBackend covers the abox.yaml backend: key through a
// real create, proving Options.BackendName is actually consumed rather than just
// populated.
//
// It deliberately does NOT use registerMockBackend: that helper selects its
// backend via ABOX_BACKEND, which outranks backend: and would make this pass
// whether or not the key is wired up. Two backends are registered and the env
// var is cleared, so only the boxfile can pick the non-default one.
func TestRunCreate_HonorsBoxfileBackend(t *testing.T) {
	isolateDataHome(t)
	backend.ResetForTesting()
	t.Cleanup(backend.ResetForTesting)

	for _, name := range []string{"autopick", "chosen"} {
		storage := t.TempDir()
		be := &mock.Backend{
			NameFunc:       func() string { return name },
			StorageDirFunc: func() string { return storage },
		}
		// "autopick" has the lower priority number, so AutoDetect prefers it.
		priority := 1
		if name == "chosen" {
			priority = 50
		}
		backend.Register(name, priority, func() backend.Backend { return be })
	}
	t.Setenv(factory.EnvBackend, "")

	path := writeBoxfile(t, "version: 1\nname: backendbox\ncpus: 2\nmemory: 4096\nbackend: chosen\n")
	opts := &Options{Factory: newTestFactory(t), FromFile: path, NoMITM: true, Brief: true}

	if err := Run(context.Background(), opts, ""); err != nil {
		t.Fatalf("Run(--from-file with backend:) error = %v", err)
	}

	inst, _, err := config.Load("backendbox")
	if err != nil {
		t.Fatalf("config.Load after create: %v", err)
	}
	if inst.Backend != "chosen" {
		t.Errorf("inst.Backend = %q, want %q: the abox.yaml backend: key must beat auto-detection",
			inst.Backend, "chosen")
	}
}

// TestCreate_RejectsMITMExceptionCoveringInjectedHost pins the interlock between
// the two keys that only became reachable together once `abox up` stopped
// dropping them. A tunneled host cannot receive an injected credential (there is
// no request to modify), so the overlap must be refused rather than silently
// producing an instance whose credential boundary does not apply.
//
// Both entry points are covered: the guard lives in box.Validate, and nothing
// else would notice if either Run or RunFromBoxfile stopped calling it.
func TestCreate_RejectsMITMExceptionCoveringInjectedHost(t *testing.T) {
	const conflicting = `version: 1
name: %s
cpus: 2
memory: 4096
http:
  mitm_exceptions:
    - example.com
  secret_injections:
    - key: token
      host: api.example.com
      header: x-api-key
`

	assertRejected := func(t *testing.T, name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("error = nil, want the exception/injection conflict to be rejected")
		}
		if !strings.Contains(err.Error(), "mitm_exceptions conflicts with secret_injections") {
			t.Errorf("error = %q, want the conflict error", err)
		}
		if config.Exists(name) {
			t.Errorf("instance %q was created despite the conflict", name)
		}
	}

	t.Run("create --from-file", func(t *testing.T) {
		isolateDataHome(t)
		registerMockBackend(t, "mock", &mock.Backend{})

		path := writeBoxfile(t, fmt.Sprintf(conflicting, "conflict-fromfile"))
		opts := &Options{Factory: newTestFactory(t), FromFile: path, Brief: true}
		assertRejected(t, "conflict-fromfile", Run(context.Background(), opts, ""))
	})

	t.Run("up", func(t *testing.T) {
		isolateDataHome(t)
		registerMockBackend(t, "mock", &mock.Backend{})

		path := writeBoxfile(t, fmt.Sprintf(conflicting, "conflict-up"))
		box, boxDir, err := boxfile.LoadFile(path)
		if err != nil {
			t.Fatalf("LoadFile: %v", err)
		}
		assertRejected(t, "conflict-up",
			RunFromBoxfile(context.Background(), newTestFactory(t), box, boxDir, true))
	})
}
