package vmrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// setLookPath swaps the PATH-resolution seam and returns a restore func. Shared by
// the portable, answer-file, and Windows test files (it lives in this untagged
// file so every build config can use it).
func setLookPath(fn func(string) (string, error)) func() {
	prev := lookPath
	lookPath = fn
	return func() { lookPath = prev }
}

// TestWindowsHostOnlyCmds pins the vnetlib argument sequence, INCLUDING the mask
// line's object token. A prior bug emitted `set vnet <vmnet> mask` (using the
// config key) instead of `set adapter <vmnet> mask`; vnetlib does not accept it.
//
// windowsHostOnlyCmds is a pure builder (netcfg.go), so this regression guard runs
// on the always-on Linux job even though the Windows provisioner is build-tagged.
func TestWindowsHostOnlyCmds(t *testing.T) {
	cfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "10.10.10.0", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}
	got := windowsHostOnlyCmds(cfg)
	want := [][]string{
		{"--", "add", "adapter", "vmnet2"},
		{"--", "set", "adapter", "vmnet2", "addr", "10.10.10.1"},
		{"--", "set", "adapter", "vmnet2", "mask", "255.255.255.0"},
		{"--", "update", "adapter", "vmnet2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("windowsHostOnlyCmds =\n%v\nwant\n%v", got, want)
	}
	// Guard against the specific regression: no command may use the "vnet" object.
	for _, c := range got {
		for _, tok := range c {
			if tok == VNetConfigKey {
				t.Errorf("command uses the %q object token (the mask bug): %v", VNetConfigKey, c)
			}
		}
	}
}

// TestResolveNetTool covers absolute-path stat, PATH lookup, and the
// names-everything-tried error.
func TestResolveNetTool(t *testing.T) {
	// Absolute path that exists.
	f := filepath.Join(t.TempDir(), "vmnet-cli")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveNetTool(f, "nope"); err != nil || got != f {
		t.Errorf("resolveNetTool(abs) = %q,%v want %q,nil", got, err, f)
	}

	// Bare name found on PATH (faked).
	defer setLookPath(func(name string) (string, error) {
		if name == "vmware-networks" {
			return "/usr/bin/vmware-networks", nil
		}
		return "", errors.New("not found")
	})()
	if got, err := resolveNetTool("vmware-networks"); err != nil || got != "/usr/bin/vmware-networks" {
		t.Errorf("resolveNetTool(bare) = %q,%v", got, err)
	}

	// None found: error names candidates.
	_, err := resolveNetTool("/nonexistent/abs", "alsonope")
	if err == nil || !strings.Contains(err.Error(), "alsonope") {
		t.Errorf("resolveNetTool(none) err = %v, want it to name the candidates", err)
	}
}

// TestResolveHostOnlyTool_Exported exercises the exported resolver used by the
// checkdeps preflight (via the current platform's candidate set).
func TestResolveHostOnlyTool_Exported(t *testing.T) {
	defer setLookPath(func(string) (string, error) { return "/usr/bin/faketool", nil })()
	if _, err := ResolveHostOnlyTool(); err != nil {
		t.Errorf("ResolveHostOnlyTool with a resolvable tool: %v", err)
	}
}

// TestCheckVMRun verifies the functional probe runs `vmrun list` and surfaces its
// error.
func TestCheckVMRun(t *testing.T) {
	t.Setenv(envVmrunHostType, "ws")
	var got []string
	restore := SetRunCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte("Total running VMs: 0\n"), nil
	})
	defer restore()
	if err := CheckVMRun(context.Background()); err != nil {
		t.Fatalf("CheckVMRun: %v", err)
	}
	want := []string{"vmrun", "-T", "ws", "list"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CheckVMRun ran %v, want %v", got, want)
	}

	restore2 := SetRunCommandForTest(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("some error"), errors.New("exit status 1")
	})
	defer restore2()
	if err := CheckVMRun(context.Background()); err == nil {
		t.Error("CheckVMRun should surface a vmrun failure")
	}
}
