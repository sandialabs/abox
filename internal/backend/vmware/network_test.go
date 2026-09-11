package vmware

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

// setupNetworkInstance persists an instance config with subnet/gateway/bridge so
// Network().Create can allocate and persist a vnet, then returns it.
func setupNetworkInstance(t *testing.T) *config.Instance {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	// Redirect the (root-owned) VMware networking answer-file to a temp path and
	// fake tool resolution so ConfigureHostOnly runs hermetically regardless of
	// the host OS. The exact per-platform command/file shape is covered by
	// internal/vmrun/netcfg_test.go; here we only exercise the backend's
	// allocate/persist/registry responsibilities.
	t.Cleanup(vmrun.SetNetworkingPathForTest(filepath.Join(t.TempDir(), "networking")))
	t.Cleanup(vmrun.SetLookPathForTest(func(name string) (string, error) { return name, nil }))
	inst := testInstance()
	inst.Subnet = "10.10.10.0/24"
	inst.Gateway = "10.10.10.1"
	inst.Bridge = config.GenerateBridgeName(inst.Name)
	p, err := config.GetPaths(inst.Name)
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	if err := config.EnsureDirs(p); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := config.Save(inst, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return inst
}

func TestNetworkCreate_AllocatesPersistsConfigures(t *testing.T) {
	inst := setupNetworkInstance(t)

	var calls [][]string
	restore := vmrun.SetRunCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	})
	defer restore()

	m := &NetworkManager{}
	if err := m.Create(context.Background(), inst); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// BackendConfig updated in memory.
	vnet, ok := inst.BackendConfig[vmrun.VNetConfigKey].(string)
	if !ok || vnet == "" {
		t.Fatalf("Create did not set BackendConfig[vnet]: %v", inst.BackendConfig)
	}
	if vnet != "vmnet2" {
		t.Errorf("first allocation = %q, want vmnet2", vnet)
	}

	// Persisted to config.yaml so VM().Create sees it.
	loaded, _, err := config.Load(inst.Name)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, _ := loaded.BackendConfig[vmrun.VNetConfigKey].(string); got != vnet {
		t.Errorf("persisted vnet = %q, want %q", got, vnet)
	}

	// Registry updated.
	if !m.Exists(inst.Bridge) {
		t.Error("Exists should report the bridge is defined after Create")
	}
	if !m.IsActive(inst.Bridge) {
		t.Error("IsActive should report the network active after Create")
	}

	// Create invoked host-only configuration (the exact per-platform command/file
	// shape is asserted in internal/vmrun/netcfg_test.go); here we only require it
	// reached the seam without issuing a forbidden uplink directive.
	if len(calls) == 0 {
		t.Fatal("Create did not invoke the network configure seam")
	}
	for _, c := range calls {
		for _, tok := range c {
			switch tok {
			case "nat", "NAT", "bridged", "bridge":
				t.Fatalf("Create issued a forbidden uplink directive %q: %v", tok, c)
			}
		}
	}
}

func TestNetworkCreate_ErrorsWhenConfigNotPersistable(t *testing.T) {
	// M2: if the vnet cannot be persisted to config.yaml (here: config not on
	// disk), Create must fail LOUDLY rather than proceed — otherwise a later
	// `abox start` would render the .vmx with the fallback bridge and point the
	// NIC at a nonexistent vmnet.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	inst := testInstance()
	inst.Subnet = "10.10.10.0/24"
	inst.Gateway = "10.10.10.1"
	inst.Bridge = config.GenerateBridgeName(inst.Name)
	// Deliberately DO NOT save the instance config to disk.

	restore := vmrun.SetRunCommandForTest(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, nil
	})
	defer restore()

	m := &NetworkManager{}
	err := m.Create(context.Background(), inst)
	if err == nil {
		t.Fatal("Create should fail when config cannot be persisted (config absent)")
	}
	if !strings.Contains(err.Error(), "persist vnet allocation") {
		t.Errorf("error should mention persist failure, got: %v", err)
	}
}

// TestNetworkCreate_ReleasesOnConfigureFailure verifies the self-cleaning Create:
// if host-only configuration fails AFTER the vmnet was allocated and persisted,
// the allocation is released back to the pool so a partial create (e.g. a
// privilege-denied answer-file write) does not permanently burn one of the ~16
// pool slots.
func TestNetworkCreate_ReleasesOnConfigureFailure(t *testing.T) {
	inst := setupNetworkInstance(t)

	// Make network-tool resolution fail so ConfigureHostOnly errors out at the
	// apply step — after Allocate has already persisted the registry entry.
	restoreLook := vmrun.SetLookPathForTest(func(string) (string, error) {
		return "", errors.New("no vmware network tool (simulated)")
	})
	defer restoreLook()

	m := &NetworkManager{}
	if err := m.Create(context.Background(), inst); err == nil {
		t.Fatal("Create should fail when host-only configuration fails")
	}

	// The allocation must have been released: no registry entry, Exists false.
	paths, err := config.GetPaths(inst.Name)
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	if got := vmrun.AllocatedInstances(registryPath(paths.Base)); len(got) != 0 {
		t.Errorf("failed Create leaked a vmnet allocation: %v", got)
	}
	if m.Exists(inst.Bridge) {
		t.Error("Exists should be false after a failed+rolled-back Create")
	}
}

func TestNetworkCreate_Idempotent(t *testing.T) {
	inst := setupNetworkInstance(t)
	restore := vmrun.SetRunCommandForTest(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, nil
	})
	defer restore()

	m := &NetworkManager{}
	if err := m.Create(context.Background(), inst); err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	first := inst.BackendConfig[vmrun.VNetConfigKey]
	if err := m.Create(context.Background(), inst); err != nil {
		t.Fatalf("Create #2: %v", err)
	}
	if inst.BackendConfig[vmrun.VNetConfigKey] != first {
		t.Errorf("idempotent Create changed vnet: %v -> %v", first, inst.BackendConfig[vmrun.VNetConfigKey])
	}
}

func TestNetworkDelete_ReleasesAndUnconfigures(t *testing.T) {
	inst := setupNetworkInstance(t)
	var calls [][]string
	restore := vmrun.SetRunCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	})
	defer restore()

	m := &NetworkManager{}
	if err := m.Create(context.Background(), inst); err != nil {
		t.Fatalf("Create: %v", err)
	}
	calls = nil // focus on Delete's calls

	if err := m.Delete(context.Background(), inst.Bridge); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if m.Exists(inst.Bridge) {
		t.Error("Exists should be false after Delete")
	}
	// Delete tore down the vmnet (releasing it from the registry) without issuing a
	// forbidden uplink directive. The exact removal mechanism (vnetlib remove vs.
	// answer-file edit + restart) is per-platform and covered in netcfg_test.go.
	for _, c := range calls {
		for _, tok := range c {
			switch tok {
			case "nat", "NAT", "bridged", "bridge":
				t.Fatalf("Delete issued a forbidden uplink directive %q: %v", tok, c)
			}
		}
	}
}

func TestNetworkDelete_IdempotentUnknownBridge(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	m := &NetworkManager{}
	// No allocation exists for this bridge; Delete must be a no-op success.
	if err := m.Delete(context.Background(), "abox-ghost"); err != nil {
		t.Fatalf("Delete of unknown bridge should be nil, got %v", err)
	}
}

func TestNetworkStartStop_Noop(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	m := &NetworkManager{}
	if err := m.Start(context.Background(), "abox-dev"); err != nil {
		t.Errorf("Start should be a no-op success, got %v", err)
	}
	if err := m.Stop(context.Background(), "abox-dev"); err != nil {
		t.Errorf("Stop should be a no-op success, got %v", err)
	}
}

func TestSubnetNetworkAddr(t *testing.T) {
	cases := map[string]string{
		"10.10.10.0/24": "10.10.10.0",
		"192.168.5.0":   "192.168.5.0",
	}
	for in, want := range cases {
		if got := subnetNetworkAddr(in); got != want {
			t.Errorf("subnetNetworkAddr(%q)=%q want %q", in, got, want)
		}
	}
}
