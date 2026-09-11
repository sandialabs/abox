//go:build darwin

package vfkit

import (
	"context"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
)

// Compile-time assertions: the backend exposes a real EgressController and, on
// darwin, receives the injected privileged PF enforcer (not the iptables one).
var (
	_ backend.EgressController = (*EgressController)(nil)
	_ backend.PfProviderSetter = (*Backend)(nil)
)

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

// instWithBridge returns an instance carrying a post-boot vmnet bridge in
// BackendConfig plus a valid /24 subnet + .1 gateway so pf rule generation
// succeeds. vfkit learns its bridge only after the VM starts (VM().Start persists
// it), so Apply — not Define — loads the anchor.
func instWithBridge() *config.Instance {
	return &config.Instance{
		Name:          "dev",
		BackendConfig: map[string]any{"bridge": "bridge100"},
		Subnet:        "192.168.128.0/24",
		Gateway:       "192.168.128.1",
		DNS:           config.DNSConfig{Port: 34711},
		HTTP:          config.HTTPConfig{Port: 45123},
	}
}

// TestDefineLoadsPreBootDeny: on a fresh start (no applied marker) vfkit's Define
// enables pf AND loads a minimal subnet-keyed default-deny into the anchor so the
// guest is fail-closed before boot. The full ruleset — which needs the post-boot
// bridge — is loaded later by Apply.
func TestDefineLoadsPreBootDeny(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{}
	e := newPfControllerWithEnforcer(f)

	inst := instWithBridge()
	if err := e.Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !f.EnableCalled {
		t.Error("Define must enable pf")
	}
	if !f.LoadCalled {
		t.Fatal("Define must load the pre-boot default-deny anchor")
	}
	if f.LoadSubnet != inst.Subnet {
		t.Errorf("pre-boot LoadAnchor subnet = %q, want %q", f.LoadSubnet, inst.Subnet)
	}
	// Pre-boot rules are subnet-only: the terminal deny, and NO bridge reference
	// (the bridge is unknown until Apply).
	if !strings.Contains(f.LoadRules, "block drop quick from "+inst.Subnet+" to any") {
		t.Errorf("pre-boot rules must contain the subnet default-deny; got:\n%s", f.LoadRules)
	}
	if strings.Contains(f.LoadRules, "bridge100") {
		t.Errorf("pre-boot rules must NOT reference the post-boot bridge; got:\n%s", f.LoadRules)
	}
	// The pre-boot deny does not write the applied marker (that signals the FULL
	// ruleset is in force, which only Apply does).
	if ok, _ := e.Verify(context.Background(), inst); ok {
		t.Error("Verify should be false before Apply writes the marker")
	}
}

// TestDefineLoadsPreBootDenyEvenWhenMarkerPresent is the MEDIUM-3 regression: the
// pre-boot deny must load regardless of the persisted "applied" marker. That marker
// lives in $TMPDIR and survives a host reboot (or an external `pfctl -F`) that wipes
// the actual kernel pf state, so gating the deny on it would skip loading while the
// anchor is empty — leaving the guest with unfiltered egress until post-boot Apply.
// Define therefore always (re)loads the deny; the only cost is a brief deny on a
// running-guest re-assert before Apply — invoked right after — restores full rules.
func TestDefineLoadsPreBootDenyEvenWhenMarkerPresent(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{}
	e := newPfControllerWithEnforcer(f)
	inst := instWithBridge()

	// Simulate a prior Apply having written the applied marker (which persists
	// across a reboot even though the kernel pf state it recorded does not).
	if err := egress.WriteMarker(inst.Name); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	if err := e.Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !f.EnableCalled {
		t.Error("Define must enable pf")
	}
	if !f.LoadCalled {
		t.Fatal("Define must load the pre-boot default-deny even when the applied marker is present")
	}
	if !strings.Contains(f.LoadRules, "block drop quick from "+inst.Subnet+" to any") {
		t.Errorf("pre-boot rules must contain the subnet default-deny; got:\n%s", f.LoadRules)
	}
}

// TestDefineFailsClosedWithoutProvider: with no injected provider, Define must
// error (fail closed) rather than silently enabling nothing.
func TestDefineFailsClosedWithoutProvider(t *testing.T) {
	isolateRuntimeDir(t)
	var e EgressController // no provider
	inst := instWithBridge()
	if err := e.Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err == nil {
		t.Fatal("Define must fail closed when no pf provider is injected")
	}
}

// TestApplyLoadsAnchorForBridge: Apply resolves the post-boot bridge, builds the
// subnet-keyed ruleset referencing that bridge, loads the anchor, and writes the
// marker so Verify becomes true.
func TestApplyLoadsAnchorForBridge(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{}
	e := newPfControllerWithEnforcer(f)

	inst := instWithBridge()
	if err := e.Apply(context.Background(), inst); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !f.LoadCalled {
		t.Fatal("Apply must load the per-instance anchor")
	}
	if f.LoadInstance != "dev" {
		t.Errorf("LoadAnchor instance = %q, want dev", f.LoadInstance)
	}
	if f.LoadSubnet != inst.Subnet {
		t.Errorf("LoadAnchor subnet = %q, want %q", f.LoadSubnet, inst.Subnet)
	}
	if !strings.Contains(f.LoadRules, "bridge100") {
		t.Errorf("LoadAnchor rules must reference the vmnet bridge; got:\n%s", f.LoadRules)
	}
	if ok, err := e.Verify(context.Background(), inst); err != nil || !ok {
		t.Errorf("Verify after Apply = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestApplyMissingBridgeErrors: with no recorded bridge (and no persisted config
// to reload), Apply cannot build rules and must error rather than load nothing.
func TestApplyMissingBridgeErrors(t *testing.T) {
	isolateRuntimeDir(t)
	f := &egress.FakeEnforcer{}
	e := newPfControllerWithEnforcer(f)

	inst := &config.Instance{Name: "no-such-instance-xyz", Subnet: "192.168.128.0/24", Gateway: "192.168.128.1"}
	if err := e.Apply(context.Background(), inst); err == nil {
		t.Fatal("Apply must error when no bridge is recorded and none can be reloaded")
	}
	if f.LoadCalled {
		t.Error("Apply must not load an anchor when the bridge is unknown")
	}
}

func TestBackendExposesEgressController(t *testing.T) {
	if New().EgressController() == nil {
		t.Fatal("Backend.EgressController() must be non-nil")
	}
}

// TestSetPfProviderInjection exercises the factory injection path: before
// injection privileged operations fail closed; after SetPfProvider they reach the
// injected enforcer.
func TestSetPfProviderInjection(t *testing.T) {
	isolateRuntimeDir(t)
	b := New()

	setter, ok := b.(backend.PfProviderSetter)
	if !ok {
		t.Fatal("Backend must implement backend.PfProviderSetter on darwin")
	}

	inst := instWithBridge()

	// Fail-closed before any provider is injected (Define enables pf).
	if err := b.EgressController().Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err == nil {
		t.Fatal("Define must fail before a pf provider is injected")
	}

	f := &egress.FakeEnforcer{}
	setter.SetPfProvider(egress.StaticProvider(f))

	if err := b.EgressController().Apply(context.Background(), inst); err != nil {
		t.Fatalf("Apply after injection: %v", err)
	}
	if !f.LoadCalled || f.LoadInstance != "dev" {
		t.Fatalf("injected enforcer not reached: loadCalled=%v instance=%q", f.LoadCalled, f.LoadInstance)
	}
}
