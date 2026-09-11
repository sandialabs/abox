package start

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdStart_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdStart(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"myvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if len(gotOpts.Names) != 1 || gotOpts.Names[0] != "myvm" {
		t.Errorf("Names = %v, want [myvm]", gotOpts.Names)
	}
}

func TestNewCmdStart_RequiresName(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdStart(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no name provided")
	}
}

// testInstance returns a minimal instance with monitoring disabled so
// startVMAndApplyFilter exercises only the VM-start + egress-apply seam
// (no monitor daemon spawn, no cloud-init).
func testInstance() *config.Instance {
	return &config.Instance{
		Name:    "fcvm",
		Bridge:  "abox-fcvm",
		Monitor: config.MonitorConfig{Enabled: false},
	}
}

// TestStartVMAndApplyFilter_FailClosedOnApplyError verifies the security-critical
// fail-closed invariant: if EgressController().Apply fails AFTER the VM has
// started, startVMAndApplyFilter force-stops the VM (so no unfiltered sandbox is
// left running) and returns the original Apply error.
func TestStartVMAndApplyFilter_FailClosedOnApplyError(t *testing.T) {
	applyErr := errors.New("boom: could not install pf anchor")

	var (
		vmStarted     bool
		forceStopSeen bool
	)

	vm := &mock.VMManager{
		StartFunc: func(ctx context.Context, name string) error {
			vmStarted = true
			return nil
		},
		ForceStopFunc: func(ctx context.Context, name string) error {
			forceStopSeen = true
			return nil
		},
	}
	ec := &mock.EgressController{
		ApplyFunc: func(ctx context.Context, inst *config.Instance) error {
			return applyErr
		},
	}
	be := &mock.Backend{
		VMFunc:               func() backend.VMManager { return vm },
		EgressControllerFunc: func() backend.EgressController { return ec },
	}

	var buf bytes.Buffer
	err := startVMAndApplyFilter(context.Background(), &buf, be, "fcvm", testInstance(), &config.Paths{})

	if err == nil {
		t.Fatal("expected an error when Apply fails, got nil")
	}
	if !errors.Is(err, applyErr) {
		t.Errorf("expected returned error to wrap the original Apply error, got: %v", err)
	}
	if !vmStarted {
		t.Error("expected the VM to have been started before Apply was attempted")
	}
	if !forceStopSeen {
		t.Error("fail-closed violated: VM().ForceStop was not called after Apply failed")
	}
}

// TestStartVMAndApplyFilter_ForceStopErrorDoesNotMaskApplyError verifies that when
// the fail-closed ForceStop itself fails, the original (more actionable) Apply
// error is still what the caller sees.
func TestStartVMAndApplyFilter_ForceStopErrorDoesNotMaskApplyError(t *testing.T) {
	applyErr := errors.New("boom: apply failed")

	vm := &mock.VMManager{
		ForceStopFunc: func(ctx context.Context, name string) error {
			return errors.New("force stop also failed")
		},
	}
	ec := &mock.EgressController{
		ApplyFunc: func(ctx context.Context, inst *config.Instance) error {
			return applyErr
		},
	}
	be := &mock.Backend{
		VMFunc:               func() backend.VMManager { return vm },
		EgressControllerFunc: func() backend.EgressController { return ec },
	}

	var buf bytes.Buffer
	err := startVMAndApplyFilter(context.Background(), &buf, be, "fcvm", testInstance(), &config.Paths{})

	if !errors.Is(err, applyErr) {
		t.Errorf("expected the original Apply error to be surfaced, got: %v", err)
	}
	// A best-effort force-stop failure must still warn the user in the output.
	if !strings.Contains(buf.String(), "could not stop VM") {
		t.Errorf("expected a warning about the failed force-stop in output, got:\n%s", buf.String())
	}
}

// TestStartVMAndApplyFilter_NoEgressControllerNoForceStop verifies the nil-gate:
// when a backend has no EgressController, startVMAndApplyFilter must not attempt
// Apply and must NOT force-stop the (successfully started) VM.
func TestStartVMAndApplyFilter_NoEgressControllerNoForceStop(t *testing.T) {
	var forceStopSeen bool
	vm := &mock.VMManager{
		ForceStopFunc: func(ctx context.Context, name string) error {
			forceStopSeen = true
			return nil
		},
	}
	be := &mock.Backend{
		VMFunc:               func() backend.VMManager { return vm },
		EgressControllerFunc: func() backend.EgressController { return nil },
	}

	var buf bytes.Buffer
	err := startVMAndApplyFilter(context.Background(), &buf, be, "fcvm", testInstance(), &config.Paths{})

	if err != nil {
		t.Fatalf("expected no error when there is no egress controller, got: %v", err)
	}
	if forceStopSeen {
		t.Error("VM was force-stopped even though no egress enforcement applies")
	}
}

// stubDaemonStarts replaces the daemon-start seams with no-ops (so recoverDaemons
// tests spawn no real child processes) and installs the given ApplyFiltered
// stand-in, restoring all four seams on cleanup.
func stubDaemonStarts(t *testing.T, apply func(w io.Writer, name string, be backend.Backend, brief bool) error) {
	t.Helper()
	origDNS, origHTTP, origMon, origApply := startDNSFilterFn, startHTTPFilterFn, startMonitorDaemonFn, applyFilteredFn
	t.Cleanup(func() {
		startDNSFilterFn, startHTTPFilterFn, startMonitorDaemonFn, applyFilteredFn = origDNS, origHTTP, origMon, origApply
	})
	noop := func(w io.Writer, name string, paths *config.Paths, logLevel string) error { return nil }
	startDNSFilterFn = noop
	startHTTPFilterFn = noop
	startMonitorDaemonFn = func(w io.Writer, name string, paths *config.Paths) error { return nil }
	applyFilteredFn = apply
}

// TestRecoverDaemons_ReassertsEgress verifies that when the backend enforces
// egress, recoverDaemons re-asserts host egress via ApplyFiltered. This path is
// the ONLY egress re-assertion on `abox start` against an already-running VM, and
// darwin's marker-based VerifyEnforced explicitly relies on it.
func TestRecoverDaemons_ReassertsEgress(t *testing.T) {
	var applyCalled bool
	stubDaemonStarts(t, func(w io.Writer, name string, be backend.Backend, brief bool) error {
		applyCalled = true
		return nil
	})
	be := &mock.Backend{
		EgressControllerFunc: func() backend.EgressController { return &mock.EgressController{} },
	}

	var buf bytes.Buffer
	if err := recoverDaemons(&buf, be, "fcvm", testInstance(), &config.Paths{}, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applyCalled {
		t.Error("egress re-assert (ApplyFiltered) was not invoked for an egress-enforcing backend")
	}
}

// TestRecoverDaemons_NoEgressControllerSkipsReassert verifies the nil-gate: a
// backend with no EgressController must not attempt the egress re-assert.
func TestRecoverDaemons_NoEgressControllerSkipsReassert(t *testing.T) {
	var applyCalled bool
	stubDaemonStarts(t, func(w io.Writer, name string, be backend.Backend, brief bool) error {
		applyCalled = true
		return nil
	})
	be := &mock.Backend{
		EgressControllerFunc: func() backend.EgressController { return nil },
	}

	var buf bytes.Buffer
	if err := recoverDaemons(&buf, be, "fcvm", testInstance(), &config.Paths{}, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if applyCalled {
		t.Error("ApplyFiltered was invoked for a backend with no egress controller")
	}
}

// TestRecoverDaemons_ApplyFilteredErrorWrapped verifies a re-assert failure is
// wrapped and surfaced (not swallowed) — a regression here would silently leave a
// restarted instance without its host egress rules re-loaded.
func TestRecoverDaemons_ApplyFilteredErrorWrapped(t *testing.T) {
	applyErr := errors.New("boom: could not re-load egress rules")
	stubDaemonStarts(t, func(w io.Writer, name string, be backend.Backend, brief bool) error {
		return applyErr
	})
	be := &mock.Backend{
		EgressControllerFunc: func() backend.EgressController { return &mock.EgressController{} },
	}

	var buf bytes.Buffer
	err := recoverDaemons(&buf, be, "fcvm", testInstance(), &config.Paths{}, true)
	if !errors.Is(err, applyErr) {
		t.Errorf("expected the ApplyFiltered error to be wrapped and returned, got: %v", err)
	}
}

// TestStartVMAndApplyFilter_SuccessKeepsVMRunning verifies the happy path: when
// Apply succeeds, the VM is left running and no force-stop occurs.
func TestStartVMAndApplyFilter_SuccessKeepsVMRunning(t *testing.T) {
	var (
		applyCalled   bool
		forceStopSeen bool
	)
	vm := &mock.VMManager{
		ForceStopFunc: func(ctx context.Context, name string) error {
			forceStopSeen = true
			return nil
		},
	}
	ec := &mock.EgressController{
		ApplyFunc: func(ctx context.Context, inst *config.Instance) error {
			applyCalled = true
			return nil
		},
	}
	be := &mock.Backend{
		VMFunc:               func() backend.VMManager { return vm },
		EgressControllerFunc: func() backend.EgressController { return ec },
	}

	var buf bytes.Buffer
	if err := startVMAndApplyFilter(context.Background(), &buf, be, "fcvm", testInstance(), &config.Paths{}); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if !applyCalled {
		t.Error("expected egress Apply to be called")
	}
	if forceStopSeen {
		t.Error("VM was force-stopped on the success path")
	}
}
