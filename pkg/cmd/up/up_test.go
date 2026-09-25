package up

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/iostreams"
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
