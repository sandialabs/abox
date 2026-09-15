package vmware

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/backendtest"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

func testInstance() *config.Instance {
	return &config.Instance{
		Version:    config.CurrentInstanceVersion,
		Name:       "dev",
		Base:       "ubuntu-24.04",
		CPUs:       2,
		Memory:     4096,
		Bridge:     "vmnet7",
		MACAddress: "00:0c:29:ab:cd:ef",
		Disk:       "20G",
	}
}

// setupPaths creates a temp abox data dir, persists a default-storage instance
// config (so config.Load — which the lifecycle methods use to resolve the .vmx —
// succeeds), and returns the resolved paths.
func setupPaths(t *testing.T) *config.Paths {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", backendtest.ShortDataHome(t))
	inst := testInstance()
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
	return p
}

func TestCreateWritesVMX(t *testing.T) {
	paths := setupPaths(t)
	m := &VMManager{}

	if err := m.Create(context.Background(), testInstance(), paths, backend.VMCreateOptions{AssumeCloudInitExists: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	vmxPath := vmrun.VMXPath(paths)
	data, err := os.ReadFile(vmxPath)
	if err != nil {
		t.Fatalf("read vmx: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		`ethernet0.vnet = "vmnet7"`,
		`scsi0:0.fileName = "disk.vmdk"`,
		`memsize = "4096"`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("vmx missing %q", want)
		}
	}

	if !m.Exists("dev") {
		t.Error("Exists should be true after Create")
	}

	// Verify 0o600 perms. Windows does not model Unix permission bits (Go reports
	// 0666/0444 from the read-only attribute), so this check is unix-only.
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(vmxPath)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("vmx perms = %o want 600", info.Mode().Perm())
		}
	}
}

func TestGetUUIDRoundTrip(t *testing.T) {
	paths := setupPaths(t)
	m := &VMManager{}
	const uuid = "56 4d aa bb cc dd ee ff-00 11 22 33 44 55 66 77"

	if err := m.Create(context.Background(), testInstance(), paths, backend.VMCreateOptions{UUID: uuid}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := m.GetUUID("dev"); got != uuid {
		t.Errorf("GetUUID = %q want %q", got, uuid)
	}
}

func TestGetUUIDMissing(t *testing.T) {
	setupPaths(t)
	m := &VMManager{}
	if got := m.GetUUID("dev"); got != "" {
		t.Errorf("GetUUID for nonexistent = %q want empty", got)
	}
}

func TestRedefinePreservesUUID(t *testing.T) {
	paths := setupPaths(t)
	m := &VMManager{}

	if err := m.Create(context.Background(), testInstance(), paths, backend.VMCreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	orig := m.GetUUID("dev")
	if orig == "" {
		t.Fatal("expected a generated uuid after Create")
	}

	// Redefine with empty UUID should read back and preserve the original.
	inst := testInstance()
	inst.Memory = 8192
	if err := m.Redefine(context.Background(), inst, paths, backend.VMCreateOptions{}); err != nil {
		t.Fatalf("Redefine: %v", err)
	}
	if got := m.GetUUID("dev"); got != orig {
		t.Errorf("Redefine changed uuid: %q -> %q", orig, got)
	}
	data, _ := os.ReadFile(vmrun.VMXPath(paths))
	if !strings.Contains(string(data), `memsize = "8192"`) {
		t.Error("Redefine did not update memsize")
	}
}

func TestIsRunningAndState(t *testing.T) {
	paths := setupPaths(t)
	m := &VMManager{}
	if err := m.Create(context.Background(), testInstance(), paths, backend.VMCreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	vmxPath := vmrun.VMXPath(paths)

	// Not running.
	restore := vmrun.SetRunCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Total running VMs: 0\n"), nil
	})
	if m.IsRunning("dev") {
		t.Error("IsRunning should be false")
	}
	if s := m.State("dev"); s != backend.VMStateStopped {
		t.Errorf("State = %q want stopped", s)
	}
	restore()

	// Running.
	restore = vmrun.SetRunCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Total running VMs: 1\n" + vmxPath + "\n"), nil
	})
	defer restore()
	if !m.IsRunning("dev") {
		t.Error("IsRunning should be true")
	}
	if s := m.State("dev"); s != backend.VMStateRunning {
		t.Errorf("State = %q want running", s)
	}
}

func TestStateUnknownWhenNotDefined(t *testing.T) {
	setupPaths(t)
	m := &VMManager{}
	if s := m.State("dev"); s != backend.VMStateUnknown {
		t.Errorf("State = %q want unknown", s)
	}
}

func TestRemoveDeletesVMXNotDiskDir(t *testing.T) {
	paths := setupPaths(t)
	m := &VMManager{}
	if err := m.Create(context.Background(), testInstance(), paths, backend.VMCreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Drop a sibling file (e.g. the disk) that must survive Remove.
	sibling := filepath.Join(paths.DiskDir, "disk.vmdk")
	if err := os.WriteFile(sibling, []byte("disk"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}

	var deleteVMArgs []string
	restore := vmrun.SetRunCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		deleteVMArgs = append([]string{name}, args...)
		return nil, nil
	})
	defer restore()

	if err := m.Remove(context.Background(), "dev"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// vmrun deleteVM was invoked with the vmx path.
	if len(deleteVMArgs) == 0 || deleteVMArgs[0] != "vmrun" {
		t.Fatalf("expected vmrun invocation, got %v", deleteVMArgs)
	}
	if deleteVMArgs[len(deleteVMArgs)-1] != vmrun.VMXPath(paths) {
		t.Errorf("deleteVM last arg = %q want vmx path", deleteVMArgs[len(deleteVMArgs)-1])
	}

	// vmx gone, sibling survives.
	if _, err := os.Stat(vmrun.VMXPath(paths)); !os.IsNotExist(err) {
		t.Error("vmx should be deleted")
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Errorf("sibling file should survive Remove: %v", err)
	}
}

func TestSnapshotManagerArgVectors(t *testing.T) {
	paths := setupPaths(t)
	vmxPath := vmrun.VMXPath(paths)
	s := &SnapshotManager{}

	var got []string
	restore := vmrun.SetRunCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return nil, nil
	})
	defer restore()

	if err := s.Create(context.Background(), "dev", "snap1", "desc"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := []string{"vmrun", "-T", "ws", "snapshot", vmxPath, "snap1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Create args = %v want %v", got, want)
	}

	if err := s.Revert(context.Background(), "dev", "snap1"); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	want = []string{"vmrun", "-T", "ws", "revertToSnapshot", vmxPath, "snap1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Revert args = %v want %v", got, want)
	}
}

func TestSnapshotManagerListAndExists(t *testing.T) {
	setupPaths(t)
	s := &SnapshotManager{}
	restore := vmrun.SetRunCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Total snapshots: 2\nsnap1\nsnap2\n"), nil
	})
	defer restore()

	infos, err := s.List(context.Background(), "dev")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 2 || infos[0].Name != "snap1" {
		t.Errorf("List = %+v", infos)
	}
	if !s.Exists("dev", "snap2") {
		t.Error("Exists(snap2) should be true")
	}
	if s.Exists("dev", "nope") {
		t.Error("Exists(nope) should be false")
	}
}

func TestBackendDryRun(t *testing.T) {
	paths := setupPaths(t)
	b := New()
	var sb strings.Builder
	if err := b.DryRun(testInstance(), paths, &sb, backend.VMCreateOptions{}); err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "=== VMX ===") {
		t.Error("DryRun missing VMX header")
	}
	if !strings.Contains(out, `ethernet0.vnet = "vmnet7"`) {
		t.Error("DryRun missing vmx body")
	}
	// AssumeCloudInitExists forced on -> CDROM present even though ISO missing.
	if !strings.Contains(out, "cdrom-image") {
		t.Error("DryRun should assume cloud-init exists")
	}
}

func TestBackendSnapshotNotNil(t *testing.T) {
	if New().Snapshot() == nil {
		t.Error("Snapshot() should not be nil")
	}
}

// TestNonDefaultStorageDir is the H1 regression: an instance whose persisted
// StorageDir differs from the default must have every lifecycle op resolve the
// .vmx via that persisted storage (config.Load), not the default (config.GetPaths).
// Before the fix, Create wrote the .vmx under the custom storage but Exists/
// GetUUID/Remove/Redefine looked under the default dir and silently failed.
func TestNonDefaultStorageDir(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	storageDir := t.TempDir() // a custom, NON-default storage root

	inst := testInstance()
	inst.StorageDir = storageDir

	// Paths honoring the custom storage (this is what Create receives).
	paths, err := config.GetPathsWithStorage(inst.Name, storageDir)
	if err != nil {
		t.Fatalf("GetPathsWithStorage: %v", err)
	}
	if err := config.EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	// Persist the config so config.Load (used by the lifecycle methods) resolves
	// the custom storage.
	if err := config.Save(inst, paths); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Sanity: the custom .vmx path differs from the DEFAULT-resolved one, so a bug
	// that used GetPaths would look in the wrong place.
	defaultPaths, _ := config.GetPaths(inst.Name)
	if vmrun.VMXPath(paths) == vmrun.VMXPath(defaultPaths) {
		t.Fatalf("test setup: custom and default vmx paths coincide (%s)", vmrun.VMXPath(paths))
	}

	m := &VMManager{}
	if err := m.Create(context.Background(), inst, paths, backend.VMCreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The .vmx must live under the custom storage.
	if _, err := os.Stat(vmrun.VMXPath(paths)); err != nil {
		t.Fatalf("vmx not written under custom storage: %v", err)
	}

	// All name-only lifecycle ops must agree by resolving the custom storage.
	if !m.Exists(inst.Name) {
		t.Error("Exists should be true (must resolve custom StorageDir)")
	}
	uuid := m.GetUUID(inst.Name)
	if uuid == "" {
		t.Fatal("GetUUID should read back the uuid from the custom-storage vmx")
	}

	// Redefine with empty UUID must preserve it (proves GetUUID read the right file).
	inst2 := testInstance()
	inst2.StorageDir = storageDir
	inst2.Memory = 8192
	if err := m.Redefine(context.Background(), inst2, paths, backend.VMCreateOptions{}); err != nil {
		t.Fatalf("Redefine: %v", err)
	}
	if got := m.GetUUID(inst.Name); got != uuid {
		t.Errorf("Redefine changed uuid (wrong file resolved?): %q -> %q", uuid, got)
	}

	// Remove must delete the .vmx under the custom storage.
	restore := vmrun.SetRunCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, nil
	})
	defer restore()
	if err := m.Remove(context.Background(), inst.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(vmrun.VMXPath(paths)); !os.IsNotExist(err) {
		t.Error("Remove should delete the vmx under custom storage")
	}
	if m.Exists(inst.Name) {
		t.Error("Exists should be false after Remove")
	}
}

// TestVMXPathForMissingInstanceLoadError verifies that name-only bool methods
// treat a missing/unloadable instance as "not present" rather than panicking.
func TestVMXPathForMissingInstanceLoadError(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	m := &VMManager{}
	if m.Exists("ghost") {
		t.Error("Exists should be false for a missing instance")
	}
	if m.IsRunning("ghost") {
		t.Error("IsRunning should be false for a missing instance")
	}
	if m.State("ghost") != backend.VMStateUnknown {
		t.Error("State should be Unknown for a missing instance")
	}
	if err := m.Start(context.Background(), "ghost"); err == nil {
		t.Error("Start should return the load error for a missing instance")
	}
}
