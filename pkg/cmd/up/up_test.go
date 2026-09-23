package up

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/internal/reconcile"
	"github.com/sandialabs/abox/internal/tui"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/start"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdUp_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdUp(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--dir", "/path/to/config"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if gotOpts.Dir != "/path/to/config" {
		t.Errorf("Dir = %q, want %q", gotOpts.Dir, "/path/to/config")
	}
}

func TestNewCmdUp_SuffixFlag(t *testing.T) {
	for _, arg := range []string{"--suffix", "-s"} {
		t.Run(arg, func(t *testing.T) {
			ios, _, _, _ := iostreams.Test()
			f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

			var gotOpts *Options
			cmd := NewCmdUp(f, func(o *Options) error {
				gotOpts = o
				return nil
			})
			cmd.SetArgs([]string{arg, "1"})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotOpts == nil {
				t.Fatal("runF was not called")
			}
			if gotOpts.Suffix != "1" {
				t.Errorf("Suffix = %q, want %q", gotOpts.Suffix, "1")
			}
		})
	}
}

func TestNewCmdUp_DefaultDir(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdUp(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts.Dir != "" {
		t.Errorf("Dir = %q, want empty (default)", gotOpts.Dir)
	}
}

// registerMockBackend installs a mock backend and selects it via ABOX_BACKEND so
// the up flow resolves a backend without a hypervisor.
func registerMockBackend(t *testing.T) {
	t.Helper()
	backend.ResetForTesting()
	t.Cleanup(backend.ResetForTesting)

	storage := t.TempDir()
	be := &mock.Backend{
		NameFunc:       func() string { return "mock" },
		StorageDirFunc: func() string { return storage },
	}
	backend.Register("mock", 10, func() backend.Backend { return be })
	t.Setenv(factory.EnvBackend, "mock")
}

// stubStartPhase replaces the start.Run seam with a no-op.
//
// start.Run spawns the filter daemons as detached child processes, and under
// `go test` the executable it spawns is the test binary itself — which ignores
// the "dns serve <name>" arguments and re-runs this whole package, spawning
// another one. Their socket/PID files also live in $XDG_RUNTIME_DIR rather than
// under the instance directory, so they survive t.TempDir() cleanup and collide
// with any real instance of the same name. Nothing about the create phase needs
// a started VM, so the phase is stubbed out entirely.
func stubStartPhase(t *testing.T) {
	t.Helper()
	old := startRunFn
	startRunFn = func(context.Context, *start.Options, string) error { return nil }
	t.Cleanup(func() { startRunFn = old })
}

// TestDoNewInstance_AppliesBoxfileToInstanceConfig is the regression test for
// the bug this package shipped: doNewInstance used to hand-build create.Options
// and silently dropped http.secret_injections, http.mitm_exceptions,
// http.max_connections and monitor.kprobe_multi.
//
// It asserts against the persisted instance config, so it fails if this package
// ever stops routing through create.RunFromBoxfile — testing RunFromBoxfile
// directly would not, since the bug was in the caller.
//
// Phase 0 (create) is the phase under test. Phase 1 is stubbed (see
// stubStartPhase); phase 2 is a genuine no-op against the mock backend's egress
// controller, and there are no provision scripts — so doNewInstance is expected
// to return nil and that is asserted rather than discarded.
func TestDoNewInstance_AppliesBoxfileToInstanceConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	// Socket and PID paths derive from XDG_RUNTIME_DIR, not from the data home,
	// so it needs isolating separately or the test writes into the real one.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	registerMockBackend(t)
	stubStartPhase(t)

	dir := t.TempDir()
	content := `version: 1
name: upbox
cpus: 2
memory: 4096
disk: 20G
base: ubuntu-24.04
allowlist:
  - allowed.example.com
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
	if err := os.WriteFile(filepath.Join(dir, "abox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write abox.yaml: %v", err)
	}

	box, boxDir, err := boxfile.Load(dir)
	if err != nil {
		t.Fatalf("boxfile.Load: %v", err)
	}
	if err := box.Validate(boxDir); err != nil {
		t.Fatalf("box.Validate: %v", err)
	}

	// factory.New (not a struct literal) so the internal client/backend caches
	// are initialized; the later phases index them.
	f := factory.New()
	ios, _, _, _ := iostreams.Test()
	f.IO = ios
	f.ColorScheme = cmdutil.NewColorScheme(false)
	opts := &Options{Factory: f}

	if err := doNewInstance(context.Background(), opts, box, boxDir, tui.NoopNotifier{}); err != nil {
		t.Fatalf("doNewInstance() error = %v", err)
	}

	inst, paths, err := config.Load("upbox")
	if err != nil {
		t.Fatalf("config.Load after up: %v; the create phase did not persist an instance", err)
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
	if !strings.Contains(string(data), "allowed.example.com") {
		t.Errorf("allowlist file missing the abox.yaml domain; got:\n%s", data)
	}
}

func TestNewCmdUp_ConfPolicyFlag(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdUp(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--conf-policy", "replace"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts.ConfPolicy != "replace" {
		t.Errorf("ConfPolicy = %q, want %q", gotOpts.ConfPolicy, "replace")
	}
}

// newNonInteractiveOpts builds Options with a non-terminal IO so reconcile falls
// back to its safe default (keep) without prompting. Returns the errOut buffer
// for asserting warning output.
func newNonInteractiveOpts(t *testing.T) (*Options, *bytes.Buffer) {
	t.Helper()
	ios, _, _, errOut := iostreams.Test()
	ios.SetTerminal(false)
	f := &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
		Prompter:    cmdutil.NewLivePrompter(ios),
	}
	return &Options{Factory: f}, errOut
}

// fatalPrompter fails the test if any prompt method is invoked. syncAllowlist
// runs inside the bubbletea TUI goroutine, so it must never prompt — the
// decision is resolved before the TUI (resolveConfDecision).
type fatalPrompter struct{ t *testing.T }

func (p fatalPrompter) Confirm(string) bool { p.t.Fatal("unexpected Confirm"); return false }
func (p fatalPrompter) ConfirmWithDefault(string, bool) bool {
	p.t.Fatal("unexpected ConfirmWithDefault")
	return false
}
func (p fatalPrompter) Select(string, []cmdutil.Option) int {
	p.t.Fatal("unexpected Select")
	return -1
}
func (p fatalPrompter) SelectWithGroups(string, map[string][]cmdutil.Option, []string) int {
	p.t.Fatal("unexpected SelectWithGroups")
	return -1
}
func (p fatalPrompter) Input(string, string) string { p.t.Fatal("unexpected Input"); return "" }
func (p fatalPrompter) MultiSelect(string, []cmdutil.Option) []int {
	p.t.Fatal("unexpected MultiSelect")
	return nil
}

// TestSyncAllowlist_NeverPrompts is the regression guard for the bug where
// syncAllowlist called reconcile.Resolve from inside the TUI goroutine: even on
// an interactive terminal with an unresolved (zero-value DecisionPrompt) policy,
// it must fail safe to Keep without prompting.
func TestSyncAllowlist_NeverPrompts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(path, []byte("api.example.net\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ios, _, _, _ := iostreams.Test()
	ios.SetTerminal(true) // interactive: Resolve WOULD prompt if it were still called
	opts := &Options{Factory: &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
		Prompter:    fatalPrompter{t: t},
	}}
	// Zero value == DecisionPrompt (unresolved), the dangerous case.
	box := &boxfile.Boxfile{Name: "dev", Allowlist: []string{"example.com", "api.example.net"}}

	if err := syncAllowlist(opts, box, path, opts.Factory.IO.Out); err != nil {
		t.Fatalf("syncAllowlist failed: %v", err)
	}

	// Unresolved decision must fail safe to Keep (file untouched, example.com not restored).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(data), "example.com") {
		t.Errorf("unresolved decision must not overwrite the on-disk allowlist, got:\n%s", string(data))
	}
}

// selectPrompter returns a fixed index from Select; other methods are unused.
// Used to simulate an interactive reconcile choice in resolveConfDecision.
type selectPrompter struct{ choice int }

func (p selectPrompter) Confirm(string) bool                  { return false }
func (p selectPrompter) ConfirmWithDefault(string, bool) bool { return false }
func (p selectPrompter) Select(string, []cmdutil.Option) int  { return p.choice }
func (p selectPrompter) SelectWithGroups(string, map[string][]cmdutil.Option, []string) int {
	return -1
}
func (p selectPrompter) Input(string, string) string                { return "" }
func (p selectPrompter) MultiSelect(string, []cmdutil.Option) []int { return nil }

// resolveTestOpts builds Options whose injected Factory.Config points at an
// allowlist file seeded with onDisk, so resolveConfDecision can run without a
// real instance on disk.
func resolveTestOpts(t *testing.T, terminal bool, prompter cmdutil.Prompter, onDisk string) *Options {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(path, []byte(onDisk), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ios, _, _, _ := iostreams.Test()
	ios.SetTerminal(terminal)
	f := &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
		Prompter:    prompter,
		Config: func(string) (*config.Instance, *config.Paths, error) {
			return &config.Instance{}, &config.Paths{Allowlist: path}, nil
		},
	}
	return &Options{Factory: f}
}

func TestResolveConfDecision_ExplicitReplaceHonored(t *testing.T) {
	// A --conf-policy=replace pre-set decision is kept without prompting, even on
	// a terminal (fatalPrompter fails the test if Resolve tries to prompt).
	opts := resolveTestOpts(t, true, fatalPrompter{t: t}, "api.example.net\n")
	opts.confDecision = reconcile.DecisionReplace
	box := &boxfile.Boxfile{Name: "dev", Allowlist: []string{"example.com"}}

	resolveConfDecision(opts, box)

	if opts.confDecision != reconcile.DecisionReplace {
		t.Errorf("explicit Replace should be preserved, got %v", opts.confDecision)
	}
}

func TestResolveConfDecision_EqualKeepsWithoutPrompt(t *testing.T) {
	// On-disk set equals the declaration, so Resolve returns Keep without
	// prompting regardless of policy (fatalPrompter guards that).
	opts := resolveTestOpts(t, true, fatalPrompter{t: t}, "example.com\napi.example.net\n")
	box := &boxfile.Boxfile{Name: "dev", Allowlist: []string{"example.com", "api.example.net"}}

	resolveConfDecision(opts, box)

	if opts.confDecision != reconcile.DecisionKeep {
		t.Errorf("equal sets should resolve to Keep, got %v", opts.confDecision)
	}
}

func TestResolveConfDecision_InteractiveReplace(t *testing.T) {
	// Diverged on disk, interactive terminal, user picks "Replace" (index 1).
	// resolveConfDecision must record DecisionReplace so the later apply syncs.
	opts := resolveTestOpts(t, true, selectPrompter{choice: 1}, "api.example.net\n")
	box := &boxfile.Boxfile{Name: "dev", Allowlist: []string{"example.com", "api.example.net"}}

	resolveConfDecision(opts, box)

	if opts.confDecision != reconcile.DecisionReplace {
		t.Errorf("interactive Replace choice should resolve to Replace, got %v", opts.confDecision)
	}
}

func TestResolveConfDecision_ConfigLoadFailureLeavesDefault(t *testing.T) {
	// If the instance config can't be loaded, the decision is left at its safe
	// default (unresolved DecisionPrompt) and syncAllowlist later fails safe to Keep.
	ios, _, _, _ := iostreams.Test()
	ios.SetTerminal(true)
	opts := &Options{Factory: &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
		Prompter:    fatalPrompter{t: t},
		Config: func(string) (*config.Instance, *config.Paths, error) {
			return nil, nil, os.ErrNotExist
		},
	}}
	box := &boxfile.Boxfile{Name: "dev", Allowlist: []string{"example.com"}}

	resolveConfDecision(opts, box)

	if opts.confDecision != reconcile.DecisionPrompt {
		t.Errorf("config load failure should leave the default decision, got %v", opts.confDecision)
	}
}

func TestSyncAllowlist_KeepDoesNotClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	// On disk the user removed example.com and kept only api.example.net.
	if err := os.WriteFile(path, []byte("api.example.net\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts, _ := newNonInteractiveOpts(t)
	// abox.yaml still lists example.com — the old behavior would restore it.
	box := &boxfile.Boxfile{Name: "dev", Allowlist: []string{"example.com", "api.example.net"}}

	if err := syncAllowlist(opts, box, path, opts.Factory.IO.Out); err != nil {
		t.Fatalf("syncAllowlist failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(data), "example.com") {
		t.Errorf("non-interactive keep should NOT restore example.com, got:\n%s", string(data))
	}
}

func TestSyncAllowlist_ReplaceOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(path, []byte("api.example.net\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts, _ := newNonInteractiveOpts(t)
	opts.confDecision = reconcile.DecisionReplace
	box := &boxfile.Boxfile{Name: "dev", Allowlist: []string{"example.com", "api.example.net"}}

	if err := syncAllowlist(opts, box, path, opts.Factory.IO.Out); err != nil {
		t.Fatalf("syncAllowlist failed: %v", err)
	}

	set, err := allowlist.LoadDomainSet(path)
	if err != nil {
		t.Fatalf("LoadDomainSet failed: %v", err)
	}
	if !set["example.com"] {
		t.Error("replace should have restored example.com from abox.yaml")
	}
}

func TestWarnConfigDrift_ReportsChangedField(t *testing.T) {
	opts, errOut := newNonInteractiveOpts(t)
	box := boxfile.DefaultBoxfile()
	box.Name = "dev"
	box.CPUs = 8

	inst := &config.Instance{
		CPUs:   2, // differs from box.CPUs
		Memory: box.Memory,
		Base:   box.Base,
		Disk:   box.Disk,
		DNS:    config.DNSConfig{Upstream: box.DNS.Upstream},
		HTTP:   config.HTTPConfig{MITM: box.GetMITM(), MaxConnections: box.GetMaxConnections()},
	}

	warnConfigDrift(opts, box, inst)

	got := errOut.String()
	if !strings.Contains(got, "cpus") || !strings.Contains(got, "WARNING") {
		t.Errorf("expected a cpus drift warning, got:\n%s", got)
	}
}

func TestWarnConfigDrift_QuietWhenMatching(t *testing.T) {
	opts, errOut := newNonInteractiveOpts(t)
	box := boxfile.DefaultBoxfile()
	box.Name = "dev"

	inst := &config.Instance{
		CPUs:   box.CPUs,
		Memory: box.Memory,
		Base:   box.Base,
		Disk:   box.Disk,
		DNS:    config.DNSConfig{Upstream: box.DNS.Upstream},
		HTTP:   config.HTTPConfig{MITM: box.GetMITM(), MaxConnections: box.GetMaxConnections()},
	}

	warnConfigDrift(opts, box, inst)

	if got := errOut.String(); got != "" {
		t.Errorf("expected no output when config matches, got:\n%s", got)
	}
}
