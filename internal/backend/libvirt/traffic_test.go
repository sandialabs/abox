//go:build linux

package libvirt

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/virsh"
)

// Compile-time assertions: the controller satisfies the backend interface.
var _ backend.EgressController = (*EgressController)(nil)

// fakeEnforcer records calls to the backend.EgressEnforcer interface so tests can
// assert which bridge/policy the controller passes through, without touching
// iptables or a privilege helper. It mirrors the vmware egress_test.go fake.
type fakeEnforcer struct {
	applyBridge  string
	applyPolicy  backend.EgressPolicy
	applyCalled  bool
	removeBridge string
	removeCalled bool
	applyErr     error
	verifyBridge string
	verifyCalled bool
	verifyResult bool
	verifyErr    error
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
	return f.verifyResult, f.verifyErr
}

// newControllerWithEnforcer builds an EgressController wired to a fake enforcer.
func newControllerWithEnforcer(f *fakeEnforcer) *EgressController {
	return &EgressController{IptablesBase: egress.IptablesBase{Provider: func() (backend.EgressEnforcer, error) { return f, nil }}}
}

// virshCall is one recorded invocation of the mocked virsh commander.
type virshCall struct {
	name string
	args []string
}

// nwfilterMock is a virsh.Commander that fakes the nwfilter define/list/undefine
// subcommands used by EgressController. filterExists controls whether
// nwfilter-list reports the traffic filter as already defined (drives the
// newlyDefined guard in Define). All calls are recorded for ordering assertions.
type nwfilterMock struct {
	filterName   string
	filterExists bool
	calls        []virshCall
}

func (m *nwfilterMock) Run(name string, args ...string) (string, error) {
	m.calls = append(m.calls, virshCall{name: name, args: args})
	// args are prefixed with "-c", "qemu:///system"; the subcommand is args[2].
	sub := ""
	if len(args) >= 3 {
		sub = args[2]
	}
	switch sub {
	case "nwfilter-list":
		if m.filterExists {
			// Format: " UUID   Name"
			return "abcd-1234  " + m.filterName + "\n", nil
		}
		return "\n", nil
	case "nwfilter-dumpxml":
		if m.filterExists {
			return "<filter name='" + m.filterName + "'><uuid>abcd-1234</uuid></filter>", nil
		}
		return "", errors.New("filter not found")
	default:
		return "", nil
	}
}

func (m *nwfilterMock) RunWithStdin(name string, stdin string, args ...string) error {
	m.calls = append(m.calls, virshCall{name: name, args: args})
	return nil
}

// subcommands extracts the ordered list of virsh subcommands (args[2]) seen.
func (m *nwfilterMock) subcommands() []string {
	var out []string
	for _, c := range m.calls {
		if len(c.args) >= 3 {
			out = append(out, c.args[2])
		}
	}
	return out
}

func (m *nwfilterMock) contains(sub string) bool {
	return slices.Contains(m.subcommands(), sub)
}

func testInstance() *config.Instance {
	return &config.Instance{
		Name:       "dev",
		Bridge:     "abox-dev",
		MACAddress: "52:54:00:ab:cd:ef",
		CPUs:       2,
		DNS:        config.DNSConfig{Port: 34711},
		HTTP:       config.HTTPConfig{Port: 45123},
	}
}

// TestDefineHappyPath: Define generates+defines the nwfilter and installs the
// host rules with the instance's bridge and policy.
func TestDefineHappyPath(t *testing.T) {
	mock := &nwfilterMock{filterName: filterName("dev"), filterExists: false}
	prev := virsh.SetCommander(mock)
	defer virsh.SetCommander(prev)

	f := &fakeEnforcer{}
	e := newControllerWithEnforcer(f)

	inst := testInstance()
	p := backend.BuildEgressPolicy(inst)

	if err := e.Define(context.Background(), inst, p); err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !f.applyCalled {
		t.Fatal("Define must call enforcer.Apply")
	}
	if f.applyBridge != "abox-dev" {
		t.Errorf("enforcer bridge = %q, want abox-dev", f.applyBridge)
	}
	if f.applyPolicy != p {
		t.Errorf("enforcer policy = %+v, want %+v", f.applyPolicy, p)
	}
	if !mock.contains("nwfilter-define") {
		t.Errorf("Define must define the nwfilter; subcommands = %v", mock.subcommands())
	}
	// A newly-defined filter that succeeds must NOT be undefined.
	if mock.contains("nwfilter-undefine") {
		t.Errorf("Define happy path must not undefine the filter; subcommands = %v", mock.subcommands())
	}
}

// TestDefineRollsBackNewlyDefined: when Apply fails and the filter was newly
// defined, the newly-created filter is undefined and the error propagated.
func TestDefineRollsBackNewlyDefined(t *testing.T) {
	mock := &nwfilterMock{filterName: filterName("dev"), filterExists: false}
	prev := virsh.SetCommander(mock)
	defer virsh.SetCommander(prev)

	f := &fakeEnforcer{applyErr: errors.New("boom")}
	e := newControllerWithEnforcer(f)

	inst := testInstance()
	err := e.Define(context.Background(), inst, backend.BuildEgressPolicy(inst))
	if err == nil {
		t.Fatal("Define must propagate enforcer.Apply error")
	}
	if !strings.Contains(err.Error(), "host egress rules") {
		t.Errorf("error = %v, want wrapping 'host egress rules'", err)
	}
	if !mock.contains("nwfilter-undefine") {
		t.Errorf("Define must undefine the newly-defined filter on rollback; subcommands = %v", mock.subcommands())
	}
}

// TestDefineDoesNotUndefinePreExisting: when the filter already existed and Apply
// fails, the pre-existing filter must NOT be undefined (newlyDefined guard).
func TestDefineDoesNotUndefinePreExisting(t *testing.T) {
	mock := &nwfilterMock{filterName: filterName("dev"), filterExists: true}
	prev := virsh.SetCommander(mock)
	defer virsh.SetCommander(prev)

	f := &fakeEnforcer{applyErr: errors.New("boom")}
	e := newControllerWithEnforcer(f)

	inst := testInstance()
	if err := e.Define(context.Background(), inst, backend.BuildEgressPolicy(inst)); err == nil {
		t.Fatal("Define must propagate enforcer.Apply error")
	}
	if mock.contains("nwfilter-undefine") {
		t.Errorf("Define must NOT undefine a pre-existing filter; subcommands = %v", mock.subcommands())
	}
}

// TestDefineErrorsWhenNoProviderInjected: Enforcer error surfaces from Define.
// With no provider injected the newly-defined filter is also rolled back.
func TestDefineErrorsWhenNoProviderInjected(t *testing.T) {
	mock := &nwfilterMock{filterName: filterName("dev"), filterExists: false}
	prev := virsh.SetCommander(mock)
	defer virsh.SetCommander(prev)

	e := &EgressController{} // no enforcer provider
	inst := testInstance()
	err := e.Define(context.Background(), inst, backend.BuildEgressPolicy(inst))
	if err == nil {
		t.Fatal("Define must fail when no egress provider is injected")
	}
	if !strings.Contains(err.Error(), "enforcer not configured") {
		t.Errorf("error = %v, want mentioning 'enforcer not configured'", err)
	}
	// The newly-defined filter must be rolled back on the Enforcer path too.
	if !mock.contains("nwfilter-undefine") {
		t.Errorf("Define must undefine the newly-defined filter when the provider is missing; subcommands = %v", mock.subcommands())
	}
}

// TestGetEnforcerErrorNoProvider: Enforcer directly reports the fail-closed error.
func TestGetEnforcerErrorNoProvider(t *testing.T) {
	e := &EgressController{}
	if _, err := e.Enforcer(); err == nil {
		t.Fatal("Enforcer must error when no provider is injected")
	}
}

// TestVerifyEnforced: VerifyEnforced delegates to the enforcer's Verify, passing
// the instance bridge, and passes its (result, error) straight through. When the
// enforcer provider itself errors, it returns (false, err) without panicking.
func TestVerifyEnforced(t *testing.T) {
	t.Run("result passthrough true", func(t *testing.T) {
		f := &fakeEnforcer{verifyResult: true}
		e := newControllerWithEnforcer(f)

		inst := testInstance()
		got, err := e.VerifyEnforced(context.Background(), inst)
		if err != nil {
			t.Fatalf("VerifyEnforced: %v", err)
		}
		if !got {
			t.Errorf("VerifyEnforced = %v, want true", got)
		}
		if !f.verifyCalled {
			t.Fatal("VerifyEnforced must call enforcer.Verify")
		}
		if f.verifyBridge != "abox-dev" {
			t.Errorf("enforcer bridge = %q, want abox-dev", f.verifyBridge)
		}
	})

	t.Run("result passthrough false", func(t *testing.T) {
		f := &fakeEnforcer{verifyResult: false}
		e := newControllerWithEnforcer(f)

		got, err := e.VerifyEnforced(context.Background(), testInstance())
		if err != nil {
			t.Fatalf("VerifyEnforced: %v", err)
		}
		if got {
			t.Errorf("VerifyEnforced = %v, want false", got)
		}
	})

	t.Run("error passthrough from Verify", func(t *testing.T) {
		wantErr := errors.New("verify boom")
		f := &fakeEnforcer{verifyResult: true, verifyErr: wantErr}
		e := newControllerWithEnforcer(f)

		got, err := e.VerifyEnforced(context.Background(), testInstance())
		if !errors.Is(err, wantErr) {
			t.Errorf("error = %v, want %v", err, wantErr)
		}
		// The controller passes through the enforcer's result unchanged.
		if !got {
			t.Errorf("VerifyEnforced = %v, want true (enforcer result passed through)", got)
		}
	})

	t.Run("provider error", func(t *testing.T) {
		e := &EgressController{IptablesBase: egress.IptablesBase{Provider: func() (backend.EgressEnforcer, error) {
			return nil, errors.New("no enforcer")
		}}}

		got, err := e.VerifyEnforced(context.Background(), testInstance())
		if err == nil {
			t.Fatal("VerifyEnforced must surface the enforcer provider error")
		}
		if got {
			t.Errorf("VerifyEnforced = %v, want false on provider error", got)
		}
	})
}

// TestRemoveFlushesHostRulesThenDeletesFilter: Remove calls enforcer.Remove and
// deletes the nwfilter, and the host-rule flush is ordered before the nwfilter
// delete (the code's documented "flush host rules first" intent).
func TestRemoveFlushesHostRulesThenDeletesFilter(t *testing.T) {
	mock := &nwfilterMock{filterName: filterName("dev"), filterExists: true}
	prev := virsh.SetCommander(mock)
	defer virsh.SetCommander(prev)

	// Wrap the enforcer so we can capture WHEN Remove was called relative to the
	// virsh nwfilter-undefine. Record the number of virsh calls seen at flush time.
	f := &orderRecordingEnforcer{mock: mock}
	e := &EgressController{IptablesBase: egress.IptablesBase{Provider: func() (backend.EgressEnforcer, error) { return f, nil }}}

	inst := testInstance()
	if err := e.Remove(context.Background(), inst); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !f.removeCalled {
		t.Fatal("Remove must call enforcer.Remove to flush host rules")
	}
	if f.removeBridge != "abox-dev" {
		t.Errorf("Remove bridge = %q, want abox-dev", f.removeBridge)
	}
	if !mock.contains("nwfilter-undefine") {
		t.Errorf("Remove must delete the nwfilter; subcommands = %v", mock.subcommands())
	}
	// The host-rule flush must precede the nwfilter-undefine. At the moment Remove
	// was invoked, no nwfilter-undefine should have been recorded yet.
	if f.callsAtFlush != 0 {
		// callsAtFlush counts only nwfilter-undefine seen before flush.
		t.Errorf("host rules must be flushed before nwfilter-undefine; saw %d undefine calls before flush", f.callsAtFlush)
	}
}

// TestRemoveIdempotentWhenFilterMissing: Remove still flushes host rules and
// returns nil when the nwfilter does not exist (no undefine attempted).
func TestRemoveIdempotentWhenFilterMissing(t *testing.T) {
	mock := &nwfilterMock{filterName: filterName("dev"), filterExists: false}
	prev := virsh.SetCommander(mock)
	defer virsh.SetCommander(prev)

	f := &fakeEnforcer{}
	e := newControllerWithEnforcer(f)

	inst := testInstance()
	if err := e.Remove(context.Background(), inst); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !f.removeCalled {
		t.Fatal("Remove must flush host rules even when the filter is absent")
	}
	if mock.contains("nwfilter-undefine") {
		t.Errorf("Remove must not undefine an absent filter; subcommands = %v", mock.subcommands())
	}
}

// orderRecordingEnforcer records how many nwfilter-undefine calls the mock had
// already recorded at the moment Remove is invoked, to assert flush ordering.
type orderRecordingEnforcer struct {
	mock         *nwfilterMock
	removeCalled bool
	removeBridge string
	callsAtFlush int
}

func (o *orderRecordingEnforcer) Apply(ctx context.Context, bridge string, p backend.EgressPolicy) error {
	return nil
}

func (o *orderRecordingEnforcer) Remove(ctx context.Context, bridge string, p backend.EgressPolicy) error {
	o.removeCalled = true
	o.removeBridge = bridge
	for _, s := range o.mock.subcommands() {
		if s == "nwfilter-undefine" {
			o.callsAtFlush++
		}
	}
	return nil
}

func (o *orderRecordingEnforcer) Verify(ctx context.Context, bridge string, p backend.EgressPolicy) (bool, error) {
	return false, nil
}
