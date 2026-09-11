package instance

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/config"
)

func TestApplyFiltered_InstanceNotFound(t *testing.T) {
	// ApplyFiltered should return an error for a non-existent instance
	be := &mock.Backend{}
	err := ApplyFiltered(io.Discard, "nonexistent-instance-12345", be, false)
	if err == nil {
		t.Error("ApplyFiltered() expected error for non-existent instance, got nil")
	}
}

// saveRunningInstance writes a minimal valid instance to an isolated data dir and
// returns a mock backend whose VM reports it running, so ApplyFiltered gets past
// LoadRunning. ec is wired as the backend's EgressController.
func saveRunningInstance(t *testing.T, name string, ec backend.EgressController) backend.Backend {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	inst := &config.Instance{
		Version:   config.CurrentInstanceVersion,
		Name:      name,
		Base:      "ubuntu-24.04",
		CPUs:      2,
		Memory:    2048,
		Subnet:    "10.10.10.0/24",
		Gateway:   "10.10.10.1",
		Bridge:    config.GenerateBridgeName(name),
		IPAddress: "10.10.10.50",
		Disk:      "20G",
	}
	paths, err := config.GetPaths(name)
	if err != nil {
		t.Fatalf("GetPaths: %v", err)
	}
	if err := config.EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("Save: %v", err)
	}

	return &mock.Backend{
		VMFunc: func() backend.VMManager {
			return &mock.VMManager{IsRunningFunc: func(string) bool { return true }}
		},
		EgressControllerFunc: func() backend.EgressController { return ec },
	}
}

// TestApplyFiltered_DefinesBeforeApply verifies both halves of enforcement are
// asserted in order: Define (installs the nwfilter + host iptables rules) must
// run before Apply (binds the nwfilter to the live interface). Reversing them
// would bind a filter that references rules not yet installed.
func TestApplyFiltered_DefinesBeforeApply(t *testing.T) {
	var order []string
	ec := &mock.EgressController{
		DefineFunc: func(context.Context, *config.Instance, backend.EgressPolicy) error {
			order = append(order, "define")
			return nil
		},
		ApplyFunc: func(context.Context, *config.Instance) error {
			order = append(order, "apply")
			return nil
		},
	}
	be := saveRunningInstance(t, "dev", ec)

	if err := ApplyFiltered(io.Discard, "dev", be, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(order) != 2 || order[0] != "define" || order[1] != "apply" {
		t.Errorf("expected Define before Apply, got call order: %v", order)
	}
}

// TestApplyFiltered_RollsBackOnApplyError verifies that when Apply fails after a
// successful Define, ApplyFiltered rolls back via Remove and surfaces the
// original Apply error — never leaving a defined-but-unapplied policy behind.
func TestApplyFiltered_RollsBackOnApplyError(t *testing.T) {
	applyErr := errors.New("boom: apply failed")
	var removeCalled bool
	ec := &mock.EgressController{
		DefineFunc: func(context.Context, *config.Instance, backend.EgressPolicy) error { return nil },
		ApplyFunc:  func(context.Context, *config.Instance) error { return applyErr },
		RemoveFunc: func(context.Context, *config.Instance) error {
			removeCalled = true
			return nil
		},
	}
	be := saveRunningInstance(t, "dev", ec)

	err := ApplyFiltered(io.Discard, "dev", be, true)
	if !errors.Is(err, applyErr) {
		t.Errorf("expected the original Apply error to be surfaced, got: %v", err)
	}
	if !removeCalled {
		t.Error("expected rollback via EgressController.Remove after Apply failed")
	}
}
