//go:build darwin

package vmware

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

// The compile-time EgressController/PfProviderSetter assertions live in the
// production file (egress_darwin.go); duplicating them here would be redundant.

// newPfControllerWithEnforcer builds an EgressController wired to a shared fake pf
// enforcer via the embedded egress.PfBase.
func newPfControllerWithEnforcer(f *egress.FakeEnforcer) *EgressController {
	return &EgressController{PfBase: egress.PfBase{Provider: egress.StaticProvider(f)}}
}

// isolateRuntimeDir points the marker-file runtime dir at a per-test temp dir so
// marker writes are hermetic and deterministic.
func isolateRuntimeDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("TMPDIR", dir)
}

// instWithVNet returns an instance carrying an allocated vmnet in BackendConfig
// plus a valid /24 subnet + .1 gateway so pf rule generation succeeds.
func instWithVNet() *config.Instance {
	return &config.Instance{
		Name:          "dev",
		BackendConfig: map[string]any{vmrun.VNetConfigKey: "vmnet7"},
		Subnet:        "10.10.10.0/24",
		Gateway:       "10.10.10.1",
		DNS:           config.DNSConfig{Port: 34711},
		HTTP:          config.HTTPConfig{Port: 45123},
	}
}

func TestDefineEnablesAndLoadsAnchorForVNet(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{}
	e := newPfControllerWithEnforcer(f)

	inst := instWithVNet()
	inst.Bridge = "abox-dev" // must NOT be used as the pf bridge
	p := backend.BuildEgressPolicy(inst)

	if err := e.Define(context.Background(), inst, p); err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !f.EnableCalled {
		t.Error("Define must enable pf")
	}
	if !f.LoadCalled {
		t.Fatal("Define must load the per-instance anchor (vmware knows the vmnet pre-boot)")
	}
	if f.LoadInstance != "dev" {
		t.Errorf("LoadAnchor instance = %q, want dev", f.LoadInstance)
	}
	if f.LoadSubnet != inst.Subnet {
		t.Errorf("LoadAnchor subnet = %q, want %q", f.LoadSubnet, inst.Subnet)
	}
	// The generated ruleset must reference the vmnet interface (not inst.Bridge).
	if !strings.Contains(f.LoadRules, "vmnet7") {
		t.Errorf("LoadAnchor rules must reference the vmnet interface; got:\n%s", f.LoadRules)
	}
	if strings.Contains(f.LoadRules, "abox-dev") {
		t.Errorf("LoadAnchor rules must NOT reference inst.Bridge; got:\n%s", f.LoadRules)
	}
	// Marker written -> Verify is true and stays unprivileged.
	ok, err := e.Verify(context.Background(), inst)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify should be true after Define writes the marker")
	}
}

func TestDefineMissingVNetErrors(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{}
	e := newPfControllerWithEnforcer(f)

	inst := &config.Instance{Name: "dev"} // no BackendConfig / vnet
	if err := e.Define(context.Background(), inst, backend.EgressPolicy{}); err == nil {
		t.Fatal("Define must error when no vmnet is allocated")
	}
	if f.EnableCalled || f.LoadCalled {
		t.Error("Define must not touch the enforcer when vnet is missing")
	}
}

func TestDefinePropagatesEnforcerError(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{LoadErr: errors.New("boom")}
	e := newPfControllerWithEnforcer(f)

	if err := e.Define(context.Background(), instWithVNet(), backend.BuildEgressPolicy(instWithVNet())); err == nil {
		t.Fatal("Define must propagate LoadAnchor error")
	}
}

func TestApplyIsNoOp(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{}
	e := newPfControllerWithEnforcer(f)

	if err := e.Apply(context.Background(), instWithVNet()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.EnableCalled || f.LoadCalled || f.FlushCalled {
		t.Error("Apply must be a pure no-op (Define already loaded the anchor)")
	}
}

func TestBackendExposesEgressController(t *testing.T) {
	if New().EgressController() == nil {
		t.Fatal("Backend.EgressController() must be non-nil")
	}
}

// TestSetPfProviderInjection exercises the full injection path used by the
// factory: before injection the controller has no enforcer and privileged
// operations fail closed; after SetPfProvider they reach the injected enforcer.
func TestSetPfProviderInjection(t *testing.T) {
	isolateRuntimeDir(t)
	b := New()

	setter, ok := b.(backend.PfProviderSetter)
	if !ok {
		t.Fatal("Backend must implement backend.PfProviderSetter on darwin")
	}

	inst := instWithVNet()

	// Fail-closed before any provider is injected.
	if err := b.EgressController().Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err == nil {
		t.Fatal("Define must fail before a pf provider is injected")
	}

	f := &egress.FakeEnforcer{}
	setter.SetPfProvider(egress.StaticProvider(f))

	if err := b.EgressController().Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err != nil {
		t.Fatalf("Define after injection: %v", err)
	}
	if !f.LoadCalled || f.LoadInstance != "dev" {
		t.Fatalf("injected enforcer not reached: loadCalled=%v instance=%q", f.LoadCalled, f.LoadInstance)
	}
}
