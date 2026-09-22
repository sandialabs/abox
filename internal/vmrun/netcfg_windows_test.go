//go:build windows

package vmrun

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// TestWindowsProvisioner_Configure verifies the Windows path issues the corrected
// vnetlib sequence through the seam (regression guard for the mask bug at the
// provisioner level). Runs on the windows CI runner (the provisioner is
// build-tagged); the pure-builder guard TestWindowsHostOnlyCmds also runs on Linux.
func TestWindowsProvisioner_Configure(t *testing.T) {
	defer setLookPath(func(string) (string, error) { return "vnetlib", nil })()
	var calls [][]string
	restore := SetRunCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	})
	defer restore()

	cfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "10.10.10.0", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}
	if err := (windowsProvisioner{}).configure(context.Background(), cfg); err != nil {
		t.Fatalf("configure: %v", err)
	}
	want := [][]string{
		{"vnetlib", "--", "add", "adapter", "vmnet2"},
		{"vnetlib", "--", "set", "adapter", "vmnet2", "addr", "10.10.10.1"},
		{"vnetlib", "--", "set", "adapter", "vmnet2", "mask", "255.255.255.0"},
		{"vnetlib", "--", "update", "adapter", "vmnet2"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("vnetlib calls =\n%v\nwant\n%v", calls, want)
	}
}

// TestConfigure_GuardRejectsUplinkInConfig_Windows verifies the Windows write path
// rejects a config whose fields carry an uplink token BEFORE any command runs.
func TestConfigure_GuardRejectsUplinkInConfig_Windows(t *testing.T) {
	badCfg := HostOnlyConfig{VNet: "vmnet2", Subnet: "nat", Gateway: "10.10.10.1", Netmask: "255.255.255.0"}

	called := false
	restore := SetRunCommandForTest(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		called = true
		return nil, nil
	})
	defer restore()
	if err := (windowsProvisioner{}).configure(context.Background(), badCfg); !errors.Is(err, errUplinkForbidden) {
		t.Fatalf("windowsProvisioner.configure err = %v, want errUplinkForbidden", err)
	}
	if called {
		t.Error("windowsProvisioner.configure invoked a command despite a rejected config")
	}
}

// TestActiveProvisioner_Windows asserts the compile-time-selected provisioner is
// the vnetlib one and the candidate list leads with vnetlib.
func TestActiveProvisioner_Windows(t *testing.T) {
	p, err := activeProvisioner()
	if err != nil {
		t.Fatalf("activeProvisioner: %v", err)
	}
	if _, ok := p.(windowsProvisioner); !ok {
		t.Errorf("activeProvisioner = %T, want windowsProvisioner", p)
	}
	if got := hostOnlyToolCandidates(); got[0] != "vnetlib" {
		t.Errorf("windows first candidate = %q, want vnetlib", got[0])
	}
}
