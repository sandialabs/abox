//go:build !darwin

package vmware

import (
	"context"
	"errors"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

// The compile-time EgressController/EgressProviderSetter assertions live in the
// production file (egress_default.go); duplicating them here would be redundant.

// fakeEnforcer records calls to the backend.EgressEnforcer interface so tests can
// assert which bridge/policy the controller passes through, without touching
// iptables or a privilege helper.
type fakeEnforcer struct {
	applyBridge  string
	applyPolicy  backend.EgressPolicy
	applyCalled  bool
	removeBridge string
	removeCalled bool
	verifyBridge string
	verifyCalled bool
	verifyResult bool
	applyErr     error
}

func (f *fakeEnforcer) Apply(ctx context.Context, bridge string, p backend.EgressPolicy) error {
	f.applyCalled = true
	f.applyBridge = bridge
	f.applyPolicy = p
	return f.applyErr
}

func (f *fakeEnforcer) Remove(ctx context.Context, bridge string, p backend.EgressPolicy) error {
	f.removeCalled = true
	f.removeBridge = bridge
	return nil
}

func (f *fakeEnforcer) Verify(ctx context.Context, bridge string, p backend.EgressPolicy) (bool, error) {
	f.verifyCalled = true
	f.verifyBridge = bridge
	return f.verifyResult, nil
}

// newControllerWithEnforcer builds an EgressController wired to a fake enforcer.
func newControllerWithEnforcer(f *fakeEnforcer) *EgressController {
	return &EgressController{IptablesBase: egress.IptablesBase{Provider: func() (backend.EgressEnforcer, error) { return f, nil }}}
}

// instWithVNet returns an instance carrying an allocated vmnet in BackendConfig.
func instWithVNet() *config.Instance {
	return &config.Instance{
		Name:          "dev",
		BackendConfig: map[string]any{vmrun.VNetConfigKey: "vmnet7"},
		DNS:           config.DNSConfig{Port: 34711},
		HTTP:          config.HTTPConfig{Port: 45123},
	}
}

func TestDefineUsesVNetNotBridge(t *testing.T) {
	f := &fakeEnforcer{verifyResult: true} // Define now verifies rules are in force
	e := newControllerWithEnforcer(f)

	inst := instWithVNet()
	inst.Bridge = "abox-dev" // must NOT be used as the enforcer bridge
	p := backend.BuildEgressPolicy(inst)

	if err := e.Define(context.Background(), inst, p); err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !f.applyCalled {
		t.Fatal("Define must call enforcer.Apply")
	}
	if f.applyBridge != "vmnet7" {
		t.Errorf("enforcer bridge = %q, want vmnet7 (the vmnet, not inst.Bridge)", f.applyBridge)
	}
	if f.applyPolicy != p {
		t.Errorf("enforcer policy = %+v, want %+v", f.applyPolicy, p)
	}
	if !f.verifyCalled || f.verifyBridge != "vmnet7" {
		t.Errorf("Define must verify enforcement on vmnet7 (called=%v bridge=%q)", f.verifyCalled, f.verifyBridge)
	}
}

// TestDefineFailsClosedWhenNotEnforced is the L7 fix: if Apply reports success
// but the rules are not actually in force, Define must error rather than let an
// unfiltered guest boot.
func TestDefineFailsClosedWhenNotEnforced(t *testing.T) {
	f := &fakeEnforcer{verifyResult: false} // Apply "succeeds" but rules didn't take
	e := newControllerWithEnforcer(f)

	err := e.Define(context.Background(), instWithVNet(), backend.EgressPolicy{})
	if err == nil {
		t.Fatal("Define must fail closed when enforcement is not verified in force")
	}
	if !f.applyCalled || !f.verifyCalled {
		t.Errorf("Define must Apply then Verify (apply=%v verify=%v)", f.applyCalled, f.verifyCalled)
	}
}

func TestDefineMissingVNetErrors(t *testing.T) {
	f := &fakeEnforcer{}
	e := newControllerWithEnforcer(f)

	inst := &config.Instance{Name: "dev"} // no BackendConfig / vnet
	if err := e.Define(context.Background(), inst, backend.EgressPolicy{}); err == nil {
		t.Fatal("Define must error when no vmnet is allocated")
	}
	if f.applyCalled {
		t.Error("Define must not call the enforcer when vnet is missing")
	}
}

func TestApplyIsNoOp(t *testing.T) {
	f := &fakeEnforcer{}
	e := newControllerWithEnforcer(f)

	if err := e.Apply(context.Background(), instWithVNet()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.applyCalled || f.removeCalled || f.verifyCalled {
		t.Error("Apply must be a pure no-op and touch the enforcer for nothing")
	}
}

func TestRemoveCallsEnforcerWithVNet(t *testing.T) {
	f := &fakeEnforcer{}
	e := newControllerWithEnforcer(f)

	if err := e.Remove(context.Background(), instWithVNet()); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !f.removeCalled {
		t.Fatal("Remove must call enforcer.Remove")
	}
	if f.removeBridge != "vmnet7" {
		t.Errorf("Remove bridge = %q, want vmnet7", f.removeBridge)
	}
}

func TestRemoveMissingVNetNoOp(t *testing.T) {
	f := &fakeEnforcer{}
	e := newControllerWithEnforcer(f)

	inst := &config.Instance{Name: "dev"} // no vnet
	if err := e.Remove(context.Background(), inst); err != nil {
		t.Fatalf("Remove should be idempotent success with no vnet: %v", err)
	}
	if f.removeCalled {
		t.Error("Remove must not call the enforcer when there is no vnet to flush")
	}
}

func TestVerifyEnforcedUsesEnforcer(t *testing.T) {
	f := &fakeEnforcer{verifyResult: true}
	e := newControllerWithEnforcer(f)

	ok, err := e.VerifyEnforced(context.Background(), instWithVNet())
	if err != nil {
		t.Fatalf("VerifyEnforced: %v", err)
	}
	if !f.verifyCalled {
		t.Fatal("VerifyEnforced must call enforcer.Verify")
	}
	if f.verifyBridge != "vmnet7" {
		t.Errorf("VerifyEnforced bridge = %q, want vmnet7", f.verifyBridge)
	}
	if !ok {
		t.Error("VerifyEnforced should propagate the enforcer result")
	}
}

// TestVerifyUnprivileged confirms Verify reports from the vmnet allocation
// registry (unprivileged) and does NOT consult the privileged enforcer.
func TestVerifyUnprivileged(t *testing.T) {
	f := &fakeEnforcer{}
	e := newControllerWithEnforcer(f)

	// Point the instance at an isolated temp data dir so the registry lookup is
	// deterministic (and empty by default).
	base := t.TempDir()
	inst := &config.Instance{Name: "dev", StorageDir: base}

	// With no allocation recorded, Verify is false and the enforcer is untouched.
	ok, err := e.Verify(context.Background(), inst)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if f.verifyCalled {
		t.Fatal("Verify must NOT call the privileged enforcer (must stay unprivileged)")
	}
	if ok {
		t.Fatal("Verify should be false with no allocation")
	}
}

func TestDefinePropagatesEnforcerError(t *testing.T) {
	f := &fakeEnforcer{applyErr: errors.New("boom")}
	e := newControllerWithEnforcer(f)

	if err := e.Define(context.Background(), instWithVNet(), backend.EgressPolicy{}); err == nil {
		t.Fatal("Define must propagate enforcer.Apply error")
	}
}

func TestBackendExposesEgressController(t *testing.T) {
	b := New()
	if b.EgressController() == nil {
		t.Fatal("Backend.EgressController() must be non-nil")
	}
}

// TestSetEgressProviderInjection exercises the full injection path used by the
// factory: before injection the controller has no enforcer and privileged
// operations fail closed; after SetEgressProvider they reach the injected
// enforcer.
func TestSetEgressProviderInjection(t *testing.T) {
	b := New()

	setter, ok := b.(backend.EgressProviderSetter)
	if !ok {
		t.Fatal("Backend must implement backend.EgressProviderSetter")
	}

	inst := instWithVNet()

	// Fail-closed before any provider is injected.
	if err := b.EgressController().Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err == nil {
		t.Fatal("Define must fail before an egress provider is injected")
	}

	f := &fakeEnforcer{verifyResult: true} // Define verifies rules are in force
	setter.SetEgressProvider(func() (backend.EgressEnforcer, error) { return f, nil })

	if err := b.EgressController().Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err != nil {
		t.Fatalf("Define after injection: %v", err)
	}
	if !f.applyCalled || f.applyBridge != "vmnet7" {
		t.Fatalf("injected enforcer not reached: applyCalled=%v bridge=%q", f.applyCalled, f.applyBridge)
	}
}
