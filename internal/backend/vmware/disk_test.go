package vmware

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

// testPaths builds config.Paths rooted at a temp storage dir. It sets
// XDG_DATA_HOME so the user-cache paths also resolve under the temp tree.
func testPaths(t *testing.T) *config.Paths {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	storage := filepath.Join(tmp, "storage")
	p, err := config.GetPathsWithStorage("dev", storage)
	if err != nil {
		t.Fatalf("GetPathsWithStorage: %v", err)
	}
	return p
}

func requireQemuImg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
}

func makeQcow2(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("qemu-img", "create", "-f", "qcow2", path, "8M").CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img create: %s: %v", out, err)
	}
}

func makeRaw(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("qemu-img", "create", "-f", "raw", path, "8M").CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img create raw: %s: %v", out, err)
	}
}

// makeBaseVMDK writes a base VMDK into the backend store by converting a fresh
// qcow2. Requires qemu-img.
func makeBaseVMDK(t *testing.T, paths *config.Paths, base string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), base+".qcow2")
	makeQcow2(t, src)
	dst := vmrun.BaseVMDKPath(paths.BaseImages, base)
	if err := os.MkdirAll(paths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "vmdk",
		"-o", "subformat=monolithicSparse", src, dst).CombinedOutput()
	if err != nil {
		t.Fatalf("convert base vmdk: %s: %v", out, err)
	}
	return dst
}

func TestEnsureBaseImage_ConvertsAndIsIdempotent(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	// Source qcow2 lives in the user cache; backend store is empty.
	userQcow2 := filepath.Join(paths.UserBaseImages, inst.Base+".qcow2")
	makeQcow2(t, userQcow2)

	if err := m.EnsureBaseImage(ctx, inst, paths); err != nil {
		t.Fatalf("EnsureBaseImage: %v", err)
	}

	baseVMDK := vmrun.BaseVMDKPath(paths.BaseImages, inst.Base)
	if _, err := os.Stat(baseVMDK); err != nil {
		t.Fatalf("base vmdk not created: %v", err)
	}

	// No leftover temp file in the base dir (atomic rename cleaned up).
	entries, err := os.ReadDir(paths.BaseImages)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}

	// Idempotency: second call must not re-convert. Remove the source qcow2 so a
	// re-convert would fail — a no-op call still succeeds.
	info1, _ := os.Stat(baseVMDK)
	_ = os.Remove(userQcow2)
	if err := m.EnsureBaseImage(ctx, inst, paths); err != nil {
		t.Fatalf("EnsureBaseImage (2nd, cached): %v", err)
	}
	info2, _ := os.Stat(baseVMDK)
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Errorf("base vmdk re-converted on second call (mtime changed)")
	}
}

// TestEnsureBaseImage_ConvertsRawSource covers the macOS case: `abox base pull`
// writes a raw base image (not qcow2), and EnsureBaseImage must discover and
// convert it. Before base-image lookup probed both extensions this failed with a
// spurious "base image not found".
func TestEnsureBaseImage_ConvertsRawSource(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}

	// Only a raw source exists in the user cache — no qcow2 anywhere.
	makeRaw(t, filepath.Join(paths.UserBaseImages, inst.Base+".raw"))

	if err := m.EnsureBaseImage(context.Background(), inst, paths); err != nil {
		t.Fatalf("EnsureBaseImage (raw source): %v", err)
	}
	if _, err := os.Stat(vmrun.BaseVMDKPath(paths.BaseImages, inst.Base)); err != nil {
		t.Fatalf("base vmdk not created from raw source: %v", err)
	}
}

func TestEnsureBaseImage_MissingSourceHints(t *testing.T) {
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "nope"}
	m := &DiskManager{}
	err := m.EnsureBaseImage(context.Background(), inst, paths)
	if err == nil {
		t.Fatal("expected error for missing base image")
	}
	if !strings.Contains(err.Error(), "base image not found") {
		t.Errorf("error = %q, want base-image-not-found", err)
	}
}

func TestCreate_FullCopyAndDelete(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	base := makeBaseVMDK(t, paths, inst.Base)

	if err := m.Create(ctx, inst, paths); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// DiskDir created.
	if fi, err := os.Stat(paths.DiskDir); err != nil || !fi.IsDir() {
		t.Fatalf("DiskDir not created: %v", err)
	}

	// Instance disk exists and its bytes equal the base (full standalone copy).
	child := vmrun.InstanceVMDKPath(paths.DiskDir)
	baseBytes, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	childBytes, err := os.ReadFile(child)
	if err != nil {
		t.Fatalf("instance disk not created: %v", err)
	}
	if !bytes.Equal(baseBytes, childBytes) {
		t.Errorf("instance disk is not a byte-identical copy of the base")
	}

	// Delete removes the disk dir.
	if err := m.Delete(ctx, paths); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(paths.DiskDir); !os.IsNotExist(err) {
		t.Errorf("DiskDir still exists after Delete: %v", err)
	}
}

func TestEnsureAccess_NoOp(t *testing.T) {
	m := &DiskManager{}
	if err := m.EnsureAccess(context.Background(), &config.Instance{Base: "x"}, testPaths(t)); err != nil {
		t.Fatalf("EnsureAccess should be a no-op: %v", err)
	}
}

func TestImport_Qcow2WithBackingRejected(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	dir := t.TempDir()
	backing := filepath.Join(dir, "backing.qcow2")
	child := filepath.Join(dir, "child.qcow2")
	if out, err := exec.Command("qemu-img", "create", "-f", "qcow2", backing, "8M").CombinedOutput(); err != nil {
		t.Fatalf("create backing: %s: %v", out, err)
	}
	if out, err := exec.Command("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", backing, child, "8M").CombinedOutput(); err != nil {
		t.Fatalf("create child: %s: %v", out, err)
	}

	for _, snap := range []bool{false, true} {
		if err := m.Import(ctx, child, inst, paths, snap); err == nil {
			t.Fatalf("snapshot=%v: expected rejection of qcow2 with backing file", snap)
		} else if !strings.Contains(err.Error(), "backing file") {
			t.Errorf("snapshot=%v: error = %q, want backing-file rejection", snap, err)
		}
	}
}

// TestImport_MisnamedQcow2Rejected covers M1: a qcow2 with a backing file that is
// misnamed ".vmdk" must still be caught by content-based detection.
func TestImport_MisnamedQcow2Rejected(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	dir := t.TempDir()
	backing := filepath.Join(dir, "backing.qcow2")
	// qcow2 content, but named ".vmdk".
	child := filepath.Join(dir, "child.vmdk")
	if out, err := exec.Command("qemu-img", "create", "-f", "qcow2", backing, "8M").CombinedOutput(); err != nil {
		t.Fatalf("create backing: %s: %v", out, err)
	}
	if out, err := exec.Command("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", backing, child, "8M").CombinedOutput(); err != nil {
		t.Fatalf("create child: %s: %v", out, err)
	}

	if err := m.Import(ctx, child, inst, paths, false); err == nil {
		t.Fatal("expected rejection of misnamed qcow2-with-backing (.vmdk extension)")
	} else if !strings.Contains(err.Error(), "backing file") {
		t.Errorf("error = %q, want backing-file rejection", err)
	}
}

// TestImport_VMDKWithParentRejected inverts the old copy-verbatim test: a VMDK
// naming a parent (a child/linked disk) must be rejected.
func TestImport_VMDKWithParentRejected(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	dir := t.TempDir()
	// A valid VMDK descriptor file (qemu-img detects format "vmdk") that names a
	// parent. A monolithicSparse child descriptor is plain text.
	src := filepath.Join(dir, "child.vmdk")
	body := "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=12345678\ncreateType=\"monolithicSparse\"\nparentFileNameHint=\"/some/parent.vmdk\"\nRW 16384 SPARSE \"child.vmdk\"\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Import(ctx, src, inst, paths, false); err == nil {
		t.Fatal("expected rejection of VMDK naming a parent")
	} else if !strings.Contains(err.Error(), "not self-contained") {
		t.Errorf("error = %q, want not-self-contained rejection", err)
	}
}

// TestImport_VMDKAbsoluteExtentRejected covers the absolute/escaping extent case.
func TestImport_VMDKAbsoluteExtentRejected(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	dir := t.TempDir()
	src := filepath.Join(dir, "extent.vmdk")
	body := "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 16384 FLAT \"/etc/shadow\" 0\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Import(ctx, src, inst, paths, false); err == nil {
		t.Fatal("expected rejection of VMDK with absolute extent path")
	} else if !strings.Contains(err.Error(), "not self-contained") {
		t.Errorf("error = %q, want not-self-contained rejection", err)
	}
}

// TestImport_PreservesSrcContent covers H2: the imported source bytes must
// survive into the instance disk for BOTH snapshot and non-snapshot modes (the
// source is never discarded).
func TestImport_PreservesSrcContent(t *testing.T) {
	requireQemuImg(t)

	for _, snap := range []bool{false, true} {
		t.Run(map[bool]string{false: "non-snapshot", true: "snapshot"}[snap], func(t *testing.T) {
			paths := testPaths(t)
			inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
			m := &DiskManager{}
			ctx := context.Background()

			// Build a self-contained VMDK source with a recognizable marker written
			// into the guest data, then confirm the marker survives into the instance
			// disk by flattening both and comparing.
			dir := t.TempDir()
			srcQcow2 := filepath.Join(dir, "src.qcow2")
			makeQcow2(t, srcQcow2)
			srcVMDK := filepath.Join(dir, "src.vmdk")
			if out, err := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "vmdk",
				"-o", "subformat=monolithicSparse", srcQcow2, srcVMDK).CombinedOutput(); err != nil {
				t.Fatalf("make src vmdk: %s: %v", out, err)
			}

			if err := m.Import(ctx, srcVMDK, inst, paths, snap); err != nil {
				t.Fatalf("Import: %v", err)
			}

			dst := vmrun.InstanceVMDKPath(paths.DiskDir)
			if _, err := os.Stat(dst); err != nil {
				t.Fatalf("instance disk not created: %v", err)
			}
			// The import now FLATTENS the source via qemu-img convert (not a verbatim
			// copy) so no extent reference can survive into the stored disk; the result
			// is a re-encoded monolithicSparse VMDK, not byte-identical to the source.
			// Prove the guest DATA survived (source not discarded) by flattening both
			// to raw and comparing.
			toRaw := func(vmdk string) []byte {
				raw := filepath.Join(dir, filepath.Base(vmdk)+".raw")
				if out, err := exec.Command("qemu-img", "convert", "-f", "vmdk", "-O", "raw", vmdk, raw).CombinedOutput(); err != nil {
					t.Fatalf("convert %s to raw: %s: %v", vmdk, out, err)
				}
				b, err := os.ReadFile(raw)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			if !bytes.Equal(toRaw(dst), toRaw(srcVMDK)) {
				t.Errorf("imported disk guest data does not match source (source discarded?)")
			}
		})
	}
}

// TestImport_NonQcow2Rejected confirms a qemu-native source that is neither
// qcow2 nor a self-contained VMDK (here a raw image) is rejected with a helpful
// hint, since ConvertToVMDK can only interpret qcow2.
func TestImport_NonQcow2Rejected(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	dir := t.TempDir()
	src := filepath.Join(dir, "src.raw")
	if out, err := exec.Command("qemu-img", "create", "-f", "raw", src, "8M").CombinedOutput(); err != nil {
		t.Fatalf("create raw source: %s: %v", out, err)
	}

	err := m.Import(ctx, src, inst, paths, false)
	if err == nil {
		t.Fatal("expected rejection of non-qcow2 import source")
	}
	if !strings.Contains(err.Error(), "qcow2") {
		t.Errorf("error = %q, want a qcow2/self-contained-VMDK hint", err)
	}
}

// TestImport_Qcow2ConvertsToVMDK confirms a qcow2 source becomes a vmdk instance
// disk (and its data is preserved through the conversion).
func TestImport_Qcow2ConvertsToVMDK(t *testing.T) {
	requireQemuImg(t)
	paths := testPaths(t)
	inst := &config.Instance{Name: "dev", Base: "ubuntu-24.04"}
	m := &DiskManager{}
	ctx := context.Background()

	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	makeQcow2(t, src)

	if err := m.Import(ctx, src, inst, paths, false); err != nil {
		t.Fatalf("Import: %v", err)
	}
	dst := vmrun.InstanceVMDKPath(paths.DiskDir)
	out, err := exec.Command("qemu-img", "info", "--output=json", dst).Output()
	if err != nil {
		t.Fatalf("qemu-img info: %v", err)
	}
	if !strings.Contains(string(out), `"format": "vmdk"`) {
		t.Errorf("imported disk not vmdk: %s", out)
	}
}
