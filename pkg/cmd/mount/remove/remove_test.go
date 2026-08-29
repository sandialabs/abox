package remove

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// TestUnmountPath_ForceBypassesMountedGate verifies that --force still attempts
// teardown when the path does not look mounted. Regression guard for the switch
// to the st_dev-based IsMounted, which reports a live-but-disconnected FUSE mount
// (or any unmounted temp dir) as not mounted — the exact case --force exists for.
func TestUnmountPath_ForceBypassesMountedGate(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	// A plain temp dir shares its parent's device, so IsMounted reports false.
	target := t.TempDir()

	orig := doUnmountFn
	t.Cleanup(func() { doUnmountFn = orig })

	ios, _, _, _ := iostreams.Test()

	// Without --force, the not-mounted gate must reject.
	called := false
	doUnmountFn = func(string, bool) error { called = true; return nil }
	o := &Options{Factory: &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}}
	if err := o.unmountPath(target); err == nil {
		t.Fatal("expected 'not mounted' error without --force")
	}
	if called {
		t.Fatal("doUnmount must not run when the path is not mounted and --force is unset")
	}

	// With --force, the gate is bypassed and teardown is attempted.
	called = false
	var gotForce bool
	doUnmountFn = func(_ string, force bool) error { called = true; gotForce = force; return nil }
	o.Force = true
	if err := o.unmountPath(target); err != nil {
		t.Fatalf("unmountPath --force returned error: %v", err)
	}
	if !called {
		t.Fatal("doUnmount must run under --force even when the path is not mounted")
	}
	if !gotForce {
		t.Error("doUnmount should receive force=true")
	}
}

// TestUnmountInstance_ForceBypassesMountedGate verifies that --force still
// attempts teardown in the by-instance path when a recorded mount no longer looks
// mounted (a dead FUSE/SSHFS endpoint). Regression guard for the fix that mirrors
// unmountPath's --force gate into unmountInstance/UnmountAll.
func TestUnmountInstance_ForceBypassesMountedGate(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("HOME", t.TempDir())

	// A minimal but loadable instance config on disk.
	instDir := filepath.Join(data, "abox", "instances", "dev")
	if err := os.MkdirAll(instDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `version: 1
name: dev
cpus: 2
memory: 4096
disk: 20G
base: ubuntu-24.04
subnet: 10.10.10.0/24
gateway: 10.10.10.1
bridge: abox-dev
dns:
  port: 5353
  upstream: 8.8.8.8:53
`
	if err := os.WriteFile(filepath.Join(instDir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Record a mount whose path is a plain temp dir, so IsMounted reports false.
	mnt := t.TempDir()
	mounts := fmt.Sprintf(`{"mounts":[{"local_path":%q,"remote_path":"/home/dev","mounted_at":"2026-01-01T00:00:00Z"}]}`, mnt)
	if err := os.WriteFile(filepath.Join(instDir, "mounts.json"), []byte(mounts), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := doUnmountFn
	t.Cleanup(func() { doUnmountFn = orig })
	called := false
	var gotForce bool
	doUnmountFn = func(_ string, force bool) error { called = true; gotForce = force; return nil }

	ios, _, _, _ := iostreams.Test()
	o := &Options{
		Factory: &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)},
		Force:   true,
	}
	if err := o.unmountInstance("dev"); err != nil {
		t.Fatalf("unmountInstance --force returned error: %v", err)
	}
	if !called {
		t.Fatal("doUnmount must run under --force even when the recorded mount is not detected")
	}
	if !gotForce {
		t.Error("doUnmount should receive force=true")
	}
}

func TestNewCmdUnmount_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdUnmount(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--force", "/mnt/dev"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.Force {
		t.Error("expected Force to be true")
	}
	if gotOpts.Path != "/mnt/dev" {
		t.Errorf("Path = %q, want %q", gotOpts.Path, "/mnt/dev")
	}
}

func TestNewCmdUnmount_AllFlag(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdUnmount(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--all"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotOpts.All {
		t.Error("expected All to be true")
	}
}

func TestNewCmdUnmount_RequiresPathOrAll(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdUnmount(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no path or --all provided")
	}
}

func TestNewCmdUnmount_AllWithArgs(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdUnmount(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{"--all", "/mnt/dev"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when --all used with args")
	}
}

// TestNewCmdRemove_MirrorsUnmount verifies the `mount remove` subcommand shares
// the same flags and args behavior as the top-level unmount alias.
func TestNewCmdRemove_MirrorsUnmount(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdRemove(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--force", "/mnt/dev"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil || !gotOpts.Force || gotOpts.Path != "/mnt/dev" {
		t.Fatalf("remove did not parse flags/args like unmount: %+v", gotOpts)
	}
}
