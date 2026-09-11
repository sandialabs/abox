//go:build darwin

package egress

import (
	"context"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

// isolateRuntimeDir points the marker-file runtime dir at a per-test temp dir so
// marker writes are hermetic and deterministic.
func isolateRuntimeDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("TMPDIR", dir)
}

func inst(name string) *config.Instance { return &config.Instance{Name: name} }

// TestEnforcerFailsClosedWithoutProvider: read-only paths and privileged paths
// alike must get a clear error (never nil, nil) when no provider was injected.
func TestEnforcerFailsClosedWithoutProvider(t *testing.T) {
	var b PfBase
	if enf, err := b.Enforcer(); err == nil || enf != nil {
		t.Fatalf("Enforcer with no provider = (%v, %v), want (nil, error)", enf, err)
	}
}

// TestVerifyIsUnprivilegedAndMarkerDriven: Verify/VerifyEnforced report the
// marker state and never touch the enforcer (so status/doctor never escalate).
func TestVerifyIsUnprivilegedAndMarkerDriven(t *testing.T) {
	isolateRuntimeDir(t)
	f := &FakeEnforcer{}
	b := PfBase{Provider: StaticProvider(f)}
	i := inst("dev")

	if ok, err := b.Verify(context.Background(), i); err != nil || ok {
		t.Fatalf("Verify with no marker = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := b.VerifyEnforced(context.Background(), i); err != nil || ok {
		t.Fatalf("VerifyEnforced with no marker = (%v, %v), want (false, nil)", ok, err)
	}

	if err := WriteMarker(i.Name); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	if ok, _ := b.Verify(context.Background(), i); !ok {
		t.Error("Verify should be true after the marker is written")
	}
	if ok, _ := b.VerifyEnforced(context.Background(), i); !ok {
		t.Error("VerifyEnforced should be true after the marker is written")
	}
	if f.EnableCalled || f.LoadCalled || f.FlushCalled {
		t.Error("Verify/VerifyEnforced must NOT touch the privileged enforcer")
	}
}

// TestRemoveFlushesAnchorAndMarker: Remove flushes the per-instance anchor and
// deletes the marker (so Verify goes false), idempotently.
func TestRemoveFlushesAnchorAndMarker(t *testing.T) {
	isolateRuntimeDir(t)
	f := &FakeEnforcer{}
	b := PfBase{Provider: StaticProvider(f)}
	i := inst("dev")

	if err := WriteMarker(i.Name); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	if err := b.Remove(context.Background(), i); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !f.FlushCalled || f.FlushName != "dev" {
		t.Fatalf("Remove must flush the anchor for the instance; flushed=%v name=%q", f.FlushCalled, f.FlushName)
	}
	if MarkerExists(i.Name) {
		t.Error("Remove must delete the marker")
	}
	// Idempotent: a second Remove (marker already gone) still succeeds.
	if err := b.Remove(context.Background(), i); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}

// TestRemoveWithoutProviderStillClearsMarker: even when the enforcer cannot be
// acquired (no provider), Remove warns about the leak but still removes the
// marker and returns nil (teardown makes progress).
func TestRemoveWithoutProviderStillClearsMarker(t *testing.T) {
	isolateRuntimeDir(t)
	var b PfBase // no provider
	i := inst("dev")
	if err := WriteMarker(i.Name); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	if err := b.Remove(context.Background(), i); err != nil {
		t.Fatalf("Remove without provider should not error: %v", err)
	}
	if MarkerExists(i.Name) {
		t.Error("Remove must delete the marker even when the enforcer is unavailable")
	}
}
