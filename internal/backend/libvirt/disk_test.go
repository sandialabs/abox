//go:build linux

package libvirt

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/qemuimg"
)

// diskPaths builds config.Paths rooted under a temp storage dir, with
// XDG_DATA_HOME pointed at the temp tree so user-cache paths resolve there too.
func diskPaths(t *testing.T) *config.Paths {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	p, err := config.GetPathsWithStorage("dev", filepath.Join(tmp, "storage"))
	if err != nil {
		t.Fatalf("GetPathsWithStorage: %v", err)
	}
	return p
}

// TestPrepareDirSetsSetgidOnLeafAndParent verifies prepareDir makes both the
// leaf dir and its immediate parent setgid (so the QEMU group inherited from the
// setgid storage root propagates to every dir the caller creates, regardless of
// creation order).
func TestPrepareDirSetsSetgidOnLeafAndParent(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "instances", "dev")

	if err := prepareDir(leaf); err != nil {
		t.Fatalf("prepareDir: %v", err)
	}
	for _, d := range []string{leaf, filepath.Dir(leaf)} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if want := storageDirMode | os.ModeDir; info.Mode() != want {
			t.Errorf("dir %s mode = %v, want %v", d, info.Mode(), want)
		}
		if info.Mode()&os.ModeSetgid == 0 {
			t.Errorf("dir %s is not setgid", d)
		}
	}
}

// stubQemuImg replaces the qemu-img command builder so no real qemu-img runs.
// infoJSON is emitted as stdout for `qemu-img info ...` (consumed by BackingFile
// / Format); every other subcommand succeeds silently. It records the argv of
// each invocation into *calls.
func stubQemuImg(t *testing.T, infoJSON string, calls *[][]string) {
	t.Helper()
	restore := qemuimg.SetRunCmdForTest(func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if calls != nil {
			*calls = append(*calls, append([]string{name}, args...))
		}
		if len(args) > 0 && args[0] == "info" {
			// Emit the canned JSON on stdout so .Output() returns it.
			return exec.CommandContext(ctx, "printf", "%s", infoJSON)
		}
		if len(args) > 0 && args[0] == "convert" {
			// Simulate qemu-img writing the converted output (last positional) so the
			// caller's subsequent chmod of the instance disk succeeds.
			if dst := args[len(args)-1]; dst != "" {
				_ = os.WriteFile(dst, []byte("converted"), 0o600)
			}
			return exec.CommandContext(ctx, "true")
		}
		// create/rebase etc.: a harmless success.
		return exec.CommandContext(ctx, "true")
	})
	t.Cleanup(restore)
}

func TestDiskImportRejectsBackingFile(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(filepath.Dir(paths.Disk), 0o700); err != nil {
		t.Fatal(err)
	}
	// A source whose qemu-img info reports a non-empty backing-filename.
	src := filepath.Join(t.TempDir(), "child.qcow2")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubQemuImg(t, `{"format":"qcow2","backing-filename":"/evil/parent.qcow2"}`, nil)

	m := &DiskManager{}
	err := m.Import(context.Background(), src, fullInstance(), paths, false)
	if err == nil {
		t.Fatal("Import must reject a non-snapshot source that carries a backing file")
	}
	if !strings.Contains(err.Error(), "backing file") {
		t.Errorf("error = %q, want backing-file rejection", err)
	}
	// The source must NOT have been copied into the instance disk.
	if _, statErr := os.Stat(paths.Disk); !os.IsNotExist(statErr) {
		t.Errorf("rejected import should not create the instance disk")
	}
}

func TestDiskImportAcceptsSelfContained(t *testing.T) {
	paths := diskPaths(t)
	src := filepath.Join(t.TempDir(), "flat.qcow2")
	if err := os.WriteFile(src, []byte("self-contained-image-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Empty backing-filename => self-contained => accepted.
	var calls [][]string
	stubQemuImg(t, `{"format":"qcow2","backing-filename":""}`, &calls)

	m := &DiskManager{}
	if err := m.Import(context.Background(), src, fullInstance(), paths, false); err != nil {
		t.Fatalf("Import of a self-contained image should succeed: %v", err)
	}
	// A non-snapshot import must FLATTEN via qemu-img convert (not a verbatim copy),
	// so the stored disk provably carries no backing/data-file pointer. Assert a
	// convert from src to the instance disk was issued.
	var sawConvert bool
	for _, c := range calls {
		if len(c) > 1 && c[1] == "convert" {
			sawConvert = true
			joined := strings.Join(c, " ")
			if !strings.Contains(joined, src) || !strings.Contains(joined, paths.Disk) {
				t.Errorf("convert did not go from src %q to disk %q: %v", src, paths.Disk, c)
			}
		}
	}
	if !sawConvert {
		t.Errorf("non-snapshot import should convert (flatten); calls=%v", calls)
	}
	// The instance disk exists and carries the restrictive mode: group-read so the
	// QEMU process (inheriting the setgid storage-root group) can reach the CoW
	// layer (dynamic ownership grants owner-write at boot); nothing for others.
	info, err := os.Stat(paths.Disk)
	if err != nil {
		t.Fatalf("instance disk not created: %v", err)
	}
	if info.Mode().Perm() != diskFileMode {
		t.Errorf("disk perms = %o, want %o", info.Mode().Perm(), diskFileMode)
	}
}

func TestDiskImportSnapshotToleratesBackingAndRebases(t *testing.T) {
	paths := diskPaths(t)
	// Pre-create the local base image so GrantInstanceAccess has a real file to
	// operate on (its ACL grant is best-effort but the path must exist).
	if err := os.MkdirAll(paths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	baseImg := filepath.Join(paths.BaseImages, fullInstance().Base+".qcow2")
	if err := os.WriteFile(baseImg, []byte("base"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(t.TempDir(), "snap.qcow2")
	if err := os.WriteFile(src, []byte("snapshot-data"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls [][]string
	// A snapshot import legitimately carries a backing-file pointer: the guard runs
	// (it inspects the source) but TOLERATES the backing file, then rebases onto the
	// local base.
	stubQemuImg(t, `{"format":"qcow2","backing-filename":"/some/other.qcow2"}`, &calls)

	m := &DiskManager{}
	if err := m.Import(context.Background(), src, fullInstance(), paths, true); err != nil {
		t.Fatalf("snapshot Import: %v", err)
	}
	// A rebase must have been issued targeting the local base image.
	var sawRebase bool
	for _, c := range calls {
		if len(c) > 1 && c[1] == "rebase" {
			sawRebase = true
			joined := strings.Join(c, " ")
			if !strings.Contains(joined, baseImg) {
				t.Errorf("rebase did not target the local base %q: %v", baseImg, c)
			}
		}
	}
	if !sawRebase {
		t.Errorf("snapshot Import should rebase onto the local base; calls=%v", calls)
	}
}

// TestDiskImportSnapshotRejectsDataFile is the G1 regression: even in snapshot mode
// (where a backing file is tolerated) a qcow2 external data-file pointer must be
// rejected — rebase (-u) only rewrites the backing pointer, not a data-file, so a
// data-file would otherwise survive into the booted disk. manifest.Snapshot is
// attacker-controlled, so this path must not be a bypass.
func TestDiskImportSnapshotRejectsDataFile(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(paths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "snap.qcow2")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubQemuImg(t, `{"format":"qcow2","format-specific":{"data":{"data-file":"/etc/shadow"}}}`, nil)

	m := &DiskManager{}
	err := m.Import(context.Background(), src, fullInstance(), paths, true)
	if err == nil {
		t.Fatal("snapshot Import must reject a source carrying an external data file")
	}
	if !strings.Contains(err.Error(), "data file") {
		t.Errorf("error = %q, want external-data-file rejection", err)
	}
	if _, statErr := os.Stat(paths.Disk); !os.IsNotExist(statErr) {
		t.Errorf("rejected import should not create the instance disk")
	}
}

func TestDiskImportInspectFailurePropagates(t *testing.T) {
	paths := diskPaths(t)
	src := filepath.Join(t.TempDir(), "src.qcow2")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// info emits non-JSON -> BackingFile parse error -> Import must fail closed.
	stubQemuImg(t, "not json", nil)
	m := &DiskManager{}
	if err := m.Import(context.Background(), src, fullInstance(), paths, false); err == nil {
		t.Fatal("Import should fail when the source cannot be inspected")
	}
}

func TestDiskCreateIssuesOverlayAndSetsPerms(t *testing.T) {
	paths := diskPaths(t)
	// Base image must exist (LockBaseImage + qemuimg.Create expect the path).
	if err := os.MkdirAll(paths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	baseImg := filepath.Join(paths.BaseImages, fullInstance().Base+".qcow2")
	if err := os.WriteFile(baseImg, []byte("base"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls [][]string
	// Overlay creation is stubbed to `true`; the manager then chmods the disk it
	// expects qemu-img to have created, so create it here to model qemu-img's side
	// effect. The stub for "create" is a no-op, so pre-create the output file.
	restore := qemuimg.SetRunCmdForTest(func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, args...))
		if len(args) > 0 && args[0] == "create" {
			// Simulate qemu-img writing the overlay so PrepareForQEMU can chmod it.
			_ = os.WriteFile(paths.Disk, []byte("overlay"), 0o600)
		}
		return exec.CommandContext(ctx, "true")
	})
	t.Cleanup(restore)

	m := &DiskManager{}
	if err := m.Create(context.Background(), fullInstance(), paths); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A qemu-img create overlay must reference the base image (backing file) and
	// the instance disk output.
	var sawCreate bool
	for _, c := range calls {
		if len(c) > 1 && c[1] == "create" {
			sawCreate = true
			joined := strings.Join(c, " ")
			if !strings.Contains(joined, baseImg) {
				t.Errorf("create overlay missing base image %q: %v", baseImg, c)
			}
			if !strings.Contains(joined, paths.Disk) {
				t.Errorf("create overlay missing output disk %q: %v", paths.Disk, c)
			}
		}
	}
	if !sawCreate {
		t.Errorf("Create did not issue a qemu-img create; calls=%v", calls)
	}
}

func TestDiskDeleteRemovesDiskDir(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Disk, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &DiskManager{}
	if err := m.Delete(context.Background(), paths); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(paths.DiskDir); !os.IsNotExist(err) {
		t.Errorf("Delete should remove the disk dir, still present: %v", err)
	}
}

func TestDiskEnsureBaseImageMissingHints(t *testing.T) {
	paths := diskPaths(t)
	m := &DiskManager{}
	err := m.EnsureBaseImage(context.Background(), fullInstance(), paths)
	if err == nil {
		t.Fatal("EnsureBaseImage should error when neither store nor cache has the base")
	}
	if !strings.Contains(err.Error(), "base image not found") {
		t.Errorf("error = %q, want base-image-not-found", err)
	}
}

func TestDiskEnsureBaseImageCopiesFromUserCache(t *testing.T) {
	paths := diskPaths(t)
	// Put the base only in the user cache; the backend store is empty.
	if err := os.MkdirAll(paths.UserBaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	userBase := filepath.Join(paths.UserBaseImages, fullInstance().Base+".qcow2")
	const marker = "base-image-bytes"
	if err := os.WriteFile(userBase, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	m := &DiskManager{}
	if err := m.EnsureBaseImage(context.Background(), fullInstance(), paths); err != nil {
		t.Fatalf("EnsureBaseImage: %v", err)
	}
	stored := filepath.Join(paths.BaseImages, fullInstance().Base+".qcow2")
	got, err := os.ReadFile(stored)
	if err != nil {
		t.Fatalf("base not copied to store: %v", err)
	}
	if string(got) != marker {
		t.Errorf("stored base content = %q, want %q", got, marker)
	}
}

// TestDiskEnsureBaseImageRepairsUnreadableMode covers the self-heal path: a
// stored base that the caller owns but that is not owner-readable (e.g. left
// 0o000/0o200 by an older version) must have its mode repaired so the base lock
// (images.LockBaseImage's os.Open) and QEMU can open it. The old fast path only
// re-asserted the ACL and never chmod'd, so such a file stayed unreadable.
func TestDiskEnsureBaseImageRepairsUnreadableMode(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(paths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(paths.BaseImages, fullInstance().Base+".qcow2")
	if err := os.WriteFile(stored, []byte("base"), 0o000); err != nil {
		t.Fatal(err)
	}
	// Owner cannot even open it for reading in this state.
	if f, err := os.Open(stored); err == nil {
		f.Close()
		t.Skip("filesystem ignores the 0o000 mode (e.g. running as root); cannot exercise repair")
	}

	m := &DiskManager{}
	if err := m.EnsureBaseImage(context.Background(), fullInstance(), paths); err != nil {
		t.Fatalf("EnsureBaseImage: %v", err)
	}
	info, err := os.Stat(stored)
	if err != nil {
		t.Fatalf("stat stored base: %v", err)
	}
	if info.Mode().Perm() != roFileMode {
		t.Errorf("stored base mode = %o, want %o (owner-readable, group-readable)", info.Mode().Perm(), roFileMode)
	}
	if f, err := os.Open(stored); err != nil {
		t.Errorf("stored base still not owner-readable after repair: %v", err)
	} else {
		f.Close()
	}
}

func TestDiskExportSnapshotCopiesRaw(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const marker = "cow-layer-bytes"
	if err := os.WriteFile(paths.Disk, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "export.qcow2")

	m := &DiskManager{}
	// snapshot=true copies the raw CoW layer verbatim (no qemu-img).
	if err := m.Export(context.Background(), dst, paths, true); err != nil {
		t.Fatalf("Export(snapshot): %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("export not written: %v", err)
	}
	if string(got) != marker {
		t.Errorf("snapshot export = %q, want verbatim copy %q", got, marker)
	}
}

// TestEnsureAccessReassertsModesForOwnedFiles covers the every-boot path: for an
// instance whose disk/base/ISO are all still owned by the caller, EnsureAccess
// re-applies the group-readable modes (and the setgid dir mode) and returns no
// error. This is the normal-restart case; the not-owned skip (a readonly source
// libvirt chowned to the QEMU user at a prior boot) cannot be exercised without
// root and is covered by the e2e up-restarts case instead.
func TestEnsureAccessReassertsModesForOwnedFiles(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.BaseImages, 0o700); err != nil {
		t.Fatal(err)
	}
	baseImg := filepath.Join(paths.BaseImages, fullInstance().Base+".qcow2")
	// Seed each file with a deliberately wrong (owner-only) mode so a successful
	// re-assert is observable.
	for _, p := range []string{paths.Disk, baseImg, paths.CloudInitISO} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	m := &DiskManager{} // nil storageProvider => ensureStorageRoot is a no-op
	if err := m.EnsureAccess(context.Background(), fullInstance(), paths); err != nil {
		t.Fatalf("EnsureAccess: %v", err)
	}

	for _, tc := range []struct {
		path string
		want os.FileMode
	}{
		{paths.Disk, diskFileMode},
		{baseImg, roFileMode},
		{paths.CloudInitISO, roFileMode},
	} {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Fatalf("stat %s: %v", tc.path, err)
		}
		if info.Mode().Perm() != tc.want {
			t.Errorf("%s mode = %o, want %o", tc.path, info.Mode().Perm(), tc.want)
		}
	}
	// The instance dir must be re-asserted setgid.
	dirInfo, err := os.Stat(paths.DiskDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode()&os.ModeSetgid == 0 {
		t.Errorf("disk dir %s is not setgid after EnsureAccess: %v", paths.DiskDir, dirInfo.Mode())
	}
}

// TestEnsureAccessSkipsMissingBaseAndISO verifies EnsureAccess does not error
// when the base image and ISO are absent (only the disk is present): both are
// stat-gated before chmod.
func TestEnsureAccessSkipsMissingBaseAndISO(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Disk, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &DiskManager{}
	if err := m.EnsureAccess(context.Background(), fullInstance(), paths); err != nil {
		t.Fatalf("EnsureAccess with missing base/ISO should succeed: %v", err)
	}
}

// TestChmodIfOwnedAppliesToOwnedFile: a file the caller owns is chmod'd.
func TestChmodIfOwnedAppliesToOwnedFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := chmodIfOwned(f, roFileMode); err != nil {
		t.Fatalf("chmodIfOwned: %v", err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != roFileMode {
		t.Errorf("mode = %o, want %o", info.Mode().Perm(), roFileMode)
	}
}

// TestChmodIfOwnedRefusesSymlink: a symlink at the path is refused (fail closed)
// and its target's mode is left untouched.
func TestChmodIfOwnedRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := chmodIfOwned(link, roFileMode); err == nil {
		t.Fatal("chmodIfOwned must refuse a symlink")
	}
	// The target must not have been chmod'd through the link.
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("target mode changed through symlink: got %o, want 0600", info.Mode().Perm())
	}
}

func TestDiskExportFlattenInvokesConvert(t *testing.T) {
	paths := diskPaths(t)
	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Disk, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "flat.qcow2")

	var calls [][]string
	stubQemuImg(t, "", &calls)

	m := &DiskManager{}
	// snapshot=false flattens via qemu-img convert (compressed).
	if err := m.Export(context.Background(), dst, paths, false); err != nil {
		t.Fatalf("Export(flatten): %v", err)
	}
	var sawConvert bool
	for _, c := range calls {
		if len(c) > 1 && c[1] == "convert" {
			sawConvert = true
			joined := strings.Join(c, " ")
			if !strings.Contains(joined, paths.Disk) || !strings.Contains(joined, dst) {
				t.Errorf("convert missing src/dst: %v", c)
			}
			if !strings.Contains(joined, "-c") {
				t.Errorf("flatten export should compress (-c): %v", c)
			}
		}
	}
	if !sawConvert {
		t.Errorf("flatten Export should invoke qemu-img convert; calls=%v", calls)
	}
}
