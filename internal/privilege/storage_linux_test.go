//go:build linux

package privilege

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/sandialabs/abox/internal/rpc"
)

// TestEnsureStorageRootRejectsForeignPath verifies the security-critical
// allowlist: the helper derives the caller from the socket peer uid (allowedUID)
// and refuses any path that is not exactly <parent>/<allowedUID>, so a client can
// never provision another user's — or an arbitrary — directory. The rejection
// happens before any privileged filesystem operation, so this runs unprivileged.
func TestEnsureStorageRootRejectsForeignPath(t *testing.T) {
	s := &EgressServer{allowedUID: 4242}

	cases := []struct {
		name string
		path string
	}{
		{"another user's uid", filepath.Join(libvirtImagesParent, "1000")},
		{"the shared parent itself", libvirtImagesParent},
		{"inside the shared parent", filepath.Join(libvirtImagesParent, "4242", "instances")},
		{"traversal into parent", filepath.Join(libvirtImagesParent, "4242", "..", "0")},
		{"unclean path", "/scratch/abox/../etc"},
		{"relative path", "scratch/abox"},
		{"filesystem root", "/"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.EnsureStorageRoot(context.Background(), &rpc.EnsureStorageRootReq{Path: tc.path})
			if err == nil {
				t.Fatalf("EnsureStorageRoot(%q) with allowedUID=4242 should be rejected", tc.path)
			}
			if !strings.Contains(err.Error(), "not permitted") {
				t.Errorf("error = %q, want a 'not permitted' allowlist rejection", err)
			}
		})
	}
}

func TestValueFromQemuConf(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "qemu.conf")
	const body = `
# user = "commented-out"
   group = "libvirt-qemu"
user="qemu"
other = "ignored"
`
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := valueFromQemuConf(conf, "group"); got != "libvirt-qemu" {
		t.Errorf("group = %q, want libvirt-qemu", got)
	}
	if got := valueFromQemuConf(conf, "user"); got != "qemu" {
		t.Errorf("user = %q, want qemu (commented line must be ignored)", got)
	}
	if got := valueFromQemuConf(filepath.Join(dir, "missing.conf"), "group"); got != "" {
		t.Errorf("missing file: got %q, want empty", got)
	}
}

// TestEnsureDirSetsSetgidAfterChown verifies ensureDir converges an existing dir
// to the requested owner/mode, applying the mode (incl. setgid) AFTER chown so
// the setgid bit survives (chown clears setgid on Linux). It runs unprivileged by
// chowning the dir to the caller's own uid/gid.
func TestEnsureDirSetsSetgidAfterChown(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "root")
	uid, gid := os.Getuid(), os.Getgid()

	if err := ensureDir(dir, uid, gid, storageRootMode); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := storageRootMode | os.ModeDir; info.Mode() != want {
		t.Errorf("mode = %v, want %v (setgid must survive the chown)", info.Mode(), want)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Error("setgid bit not set on created dir")
	}
	// Idempotent: a second call converges the same dir without error.
	if err := ensureDir(dir, uid, gid, storageRootMode); err != nil {
		t.Fatalf("ensureDir (re-run): %v", err)
	}
}

// TestEnsureDirRefusesSymlink proves the O_NOFOLLOW guard: if a symlink is
// planted at the target path, ensureDir refuses it rather than following it and
// chmod/chown-ing the link's target (which, run as root in the helper, could be
// an arbitrary file an unprivileged user pointed at).
func TestEnsureDirRefusesSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "outside")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// ensureDir's Mkdir hits ErrExist (the symlink), then the O_NOFOLLOW open must
	// refuse the symlink.
	err := ensureDir(link, os.Getuid(), os.Getgid(), storageRootMode)
	if err == nil {
		t.Fatal("ensureDir must refuse a symlink at the target path")
	}
	// The target's mode must be untouched (we opened neither it nor the link).
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("symlink target mode changed to %o; O_NOFOLLOW should have refused it", info.Mode().Perm())
	}
}

// TestResolveQEMUGroupGIDPrefersQemuConf verifies the (1) qemu.conf `group=`
// preference wins over the user-group and known-name fallbacks. It points
// qemuConfPath at a temp file naming a group that exists on the test host.
func TestResolveQEMUGroupGIDPrefersQemuConf(t *testing.T) {
	// Resolve the caller's own primary group name — guaranteed to exist.
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("cannot resolve caller's primary group: %v", err)
	}

	dir := t.TempDir()
	conf := filepath.Join(dir, "qemu.conf")
	if err := os.WriteFile(conf, []byte("group = \""+g.Name+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := qemuConfPath
	qemuConfPath = conf
	t.Cleanup(func() { qemuConfPath = orig })

	gid, name, err := resolveQEMUGroupGID()
	if err != nil {
		t.Fatalf("resolveQEMUGroupGID: %v", err)
	}
	if name != g.Name || strconv.Itoa(gid) != g.Gid {
		t.Errorf("resolved %s/%d, want %s/%s from qemu.conf group=", name, gid, g.Name, g.Gid)
	}
}

// TestRegroupSubtreeConfinedAndRefusesSymlinkEscape verifies the regroup walk is
// confined to the caller's own subtree: it chgrps/chmods entries INSIDE the root
// (dirs setgid, files group-readable) and, for a symlink pointing OUTSIDE the
// root, chowns the link in place (lchown) without following it — so the walk can
// never chmod a file outside the subtree. It runs unprivileged by regrouping to
// the caller's own uid/gid.
func TestRegroupSubtreeConfinedAndRefusesSymlinkEscape(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()

	root := filepath.Join(t.TempDir(), "uid")
	if err := os.MkdirAll(filepath.Join(root, "instances", "dev"), 0o700); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(root, "instances", "dev", "disk.qcow2")
	if err := os.WriteFile(disk, []byte("d"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A read-only sibling (base image) — must gain group-read only, NOT write.
	base := filepath.Join(root, "instances", "dev", "base.qcow2")
	if err := os.WriteFile(base, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A file OUTSIDE the subtree, with a symlink to it planted INSIDE. Its mode
	// must be untouched by the walk (regroup must not follow the link).
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(outside, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "instances", "dev", "link")); err != nil {
		t.Fatal(err)
	}

	if err := regroupSubtree(root, uid, gid); err != nil {
		t.Fatalf("regroupSubtree: %v", err)
	}

	// Dirs inside the subtree are setgid.
	for _, d := range []string{root, filepath.Join(root, "instances"), filepath.Join(root, "instances", "dev")} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSetgid == 0 {
			t.Errorf("dir %s not setgid after regroup: %v", d, info.Mode())
		}
	}
	// The disk gained group-read+WRITE (owner bits preserved), no others: it is
	// the writable CoW layer, and libvirt's pre-start accessibility check runs
	// before dynamic_ownership chowns it to the QEMU user — see regroupFile.
	info, err := os.Stat(disk)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o060 != 0o060 {
		t.Errorf("disk %v missing group-read+write after regroup", info.Mode().Perm())
	}
	if info.Mode().Perm()&0o007 != 0 {
		t.Errorf("disk %v grants access to others", info.Mode().Perm())
	}
	// The read-only sibling gained group-read ONLY, no write.
	binfo, err := os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	if binfo.Mode().Perm()&0o040 == 0 {
		t.Errorf("base %v missing group-read after regroup", binfo.Mode().Perm())
	}
	if binfo.Mode().Perm()&0o020 != 0 {
		t.Errorf("base %v should not gain group-write after regroup", binfo.Mode().Perm())
	}
	if binfo.Mode().Perm()&0o007 != 0 {
		t.Errorf("base %v grants access to others", binfo.Mode().Perm())
	}
	// The out-of-subtree target's mode must be UNCHANGED (walk did not follow the link).
	oinfo, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if oinfo.Mode().Perm() != 0o600 {
		t.Errorf("out-of-subtree file mode = %o, want 600 (regroup must not follow the symlink)", oinfo.Mode().Perm())
	}
}

// TestRegroupSubtreeRefusesHardlink verifies the hardlink guard: os.Root confines
// symlink/".." traversal but NOT hardlinks (a real entry whose inode may live
// outside the subtree). A caller-planted hardlink to an out-of-tree file must be
// refused so the root-run chown/chmod cannot reach that inode.
func TestRegroupSubtreeRefusesHardlink(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()

	root := filepath.Join(t.TempDir(), "uid")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// A file outside the subtree, hard-linked INTO it. The link must be on the
	// same filesystem as the subtree, so create the target under the same TempDir.
	outside := filepath.Join(filepath.Dir(root), "secret")
	if err := os.WriteFile(outside, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	hl := filepath.Join(root, "hardlink.qcow2")
	if err := os.Link(outside, hl); err != nil {
		t.Skipf("cannot create hardlink (fs restriction): %v", err)
	}

	err := regroupSubtree(root, uid, gid)
	if err == nil {
		t.Fatal("regroupSubtree must refuse a file with extra hard links")
	}
	if !strings.Contains(err.Error(), "hard link") {
		t.Errorf("error = %q, want a hard-link refusal", err)
	}
	// The out-of-subtree target's mode must be UNCHANGED.
	oinfo, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if oinfo.Mode().Perm() != 0o600 {
		t.Errorf("out-of-subtree target mode = %o, want 600 (regroup must not touch a hardlink target)", oinfo.Mode().Perm())
	}
}

// TestEnsureStorageRootCallerOwnedRefusesRegroup verifies regroup (a recursive
// chown used only by `abox migrate`) is never applied to a user-chosen root.
func TestEnsureStorageRootCallerOwnedRefusesRegroup(t *testing.T) {
	s := &EgressServer{allowedUID: os.Getuid()}
	_, err := s.EnsureStorageRoot(context.Background(), &rpc.EnsureStorageRootReq{Path: t.TempDir(), Regroup: true})
	if err == nil || !strings.Contains(err.Error(), "regroup") {
		t.Fatalf("EnsureStorageRoot(custom, regroup) error = %v, want a regroup refusal", err)
	}
}

// TestEnsureCallerOwnedRootSharesDir verifies a caller-owned root and its
// shared subdirs end up setgid to the target group with the owner unchanged.
// It runs unprivileged by using the caller's own uid/gid.
func TestEnsureCallerOwnedRootSharesDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "abox")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	for range 2 { // idempotent
		if err := ensureCallerOwnedRoot(root, uid, gid); err != nil {
			t.Fatalf("ensureCallerOwnedRoot: %v", err)
		}
	}
	for _, dir := range []string{root, filepath.Join(root, "instances"), filepath.Join(root, "base")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if want := storageRootMode | os.ModeDir; info.Mode() != want {
			t.Errorf("%s mode = %v, want %v", dir, info.Mode(), want)
		}
		st := info.Sys().(*syscall.Stat_t)
		if int(st.Uid) != uid || int(st.Gid) != gid {
			t.Errorf("%s owner = %d:%d, want %d:%d", dir, st.Uid, st.Gid, uid, gid)
		}
	}
}

// TestEnsureCallerOwnedRootRefusesForeignOwner verifies the helper never
// touches a directory the caller does not own (e.g. /etc, another user's dir).
func TestEnsureCallerOwnedRootRefusesForeignOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	err := ensureCallerOwnedRoot(root, os.Getuid()+1, os.Getgid())
	if err == nil || !strings.Contains(err.Error(), "not the caller") {
		t.Fatalf("error = %v, want a foreign-owner refusal", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSetgid != 0 {
		t.Errorf("foreign dir mode changed to %v", info.Mode())
	}
	if _, err := os.Stat(filepath.Join(root, "instances")); !os.IsNotExist(err) {
		t.Errorf("subdir created in a foreign dir (stat err = %v)", err)
	}
}

// TestEnsureCallerOwnedRootRefusesSymlinks verifies a symlink at the root or at
// a shared subdir is refused rather than followed to its target.
func TestEnsureCallerOwnedRootRefusesSymlinks(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "outside")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureCallerOwnedRoot(link, os.Getuid(), os.Getgid()); err == nil {
		t.Error("ensureCallerOwnedRoot must refuse a symlinked root")
	}

	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "instances")); err != nil {
		t.Fatal(err)
	}
	if err := ensureCallerOwnedRoot(root, os.Getuid(), os.Getgid()); err == nil {
		t.Error("ensureCallerOwnedRoot must refuse a symlinked instances subdir")
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSetgid != 0 {
		t.Errorf("symlink target mode changed to %v; O_NOFOLLOW should have refused it", info.Mode())
	}
}

// TestCheckTraversable verifies a parent the QEMU process cannot search is
// reported, and a world-searchable one passes.
func TestCheckTraversable(t *testing.T) {
	// t.TempDir and its per-test parent are 0700; open them up so only the
	// directory under test can fail the check.
	base := t.TempDir()
	for _, d := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A gid the test dirs don't carry, so only the "other" bits count.
	const qemuGID = 4242
	if err := checkTraversable(base, qemuGID, "libvirt-qemu"); err != nil {
		t.Skipf("temp dir ancestors are not world-searchable on this host: %v", err)
	}
	parent := filepath.Join(base, "user")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	err := checkTraversable(parent, qemuGID, "libvirt-qemu")
	if err == nil || !strings.Contains(err.Error(), parent) {
		t.Fatalf("checkTraversable(0700 dir) error = %v, want one naming %s", err, parent)
	}
	if err := os.Chmod(parent, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := checkTraversable(parent, qemuGID, "libvirt-qemu"); err != nil {
		t.Errorf("checkTraversable(0711 dir) = %v, want nil", err)
	}
}

// TestEnsureCallerOwnedRootRefusesNonEmptyDir verifies a storage_dir pointed at
// a directory already in use (e.g. $HOME) is refused rather than re-grouped
// and narrowed to 2750.
func TestEnsureCallerOwnedRootRefusesNonEmptyDir(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".bashrc"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	err := ensureCallerOwnedRoot(root, os.Getuid(), gid)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("error = %v, want a non-empty refusal", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 || info.Mode()&os.ModeSetgid != 0 {
		t.Errorf("in-use dir mode changed to %v", info.Mode())
	}
}
