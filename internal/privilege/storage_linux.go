//go:build linux

package privilege

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/validation"
)

// libvirtImagesParent is the shared parent for every user's abox disk storage.
// It MUST match config.LibvirtImagesDir; it is hardcoded here (not imported) so
// the privileged helper keeps no dependency on the config package and the path
// allowlist lives, explicit, in the trusted code.
const libvirtImagesParent = "/var/lib/libvirt/images/abox"

// qemuConfPath is libvirt's qemu config, the authoritative source of the QEMU
// runtime group when its `group = "..."` line is uncommented. The helper runs as
// root so (unlike the unprivileged client) it can read it. A var so tests can
// override.
var qemuConfPath = "/etc/libvirt/qemu.conf"

// knownQEMUUsers are the usual QEMU runtime user names by distribution
// (libvirt-qemu on Debian/Ubuntu, qemu on Fedora/Arch). The QEMU process's own
// primary group is preferred over the known-group fallback (qemuDiskGroups,
// defined in privilege.go) — that list is the last resort.
var knownQEMUUsers = []string{groupLibvirtQEMU, groupQEMU}

// storageRootMode is the per-user storage-root directory mode: setgid (so images
// created underneath inherit the QEMU group), owner rwx, group r-x (traverse +
// read, no write at the root), nothing for others.
const storageRootMode = os.ModeSetgid | 0o750

// EnsureStorageRoot idempotently provisions the caller's per-user disk storage
// root — <libvirtImagesParent>/<uid> — owned by the caller (the socket peer uid)
// and setgid to the QEMU runtime group. Every disk/dir the (unprivileged) client
// then creates underneath inherits that group via setgid, so the VM process
// reads them by group membership with no ACLs and no $HOME traversal. Runs as
// root in the helper. Idempotent: re-running converges owner and mode.
func (s *EgressServer) EnsureStorageRoot(_ context.Context, req *rpc.EnsureStorageRootReq) (*rpc.Empty, error) {
	// Derive the caller from the socket peer credentials (allowedUID), NOT from
	// the request, and require the requested path to be exactly that user's own
	// subdir. This makes the operation an allowlist of one: a client can never
	// provision another user's — or an arbitrary — directory.
	uid := s.allowedUID
	want := filepath.Join(libvirtImagesParent, strconv.Itoa(uid))
	if filepath.Clean(req.GetPath()) != want {
		// Not the default root: the only other thing a caller may ask for is to
		// group-share a directory it already owns (a user-configured
		// storage_dir). That path is never created or chowned by root; see
		// ensureCallerOwnedRoot.
		if err := validation.ValidateStorageRoot(req.GetPath(), libvirtImagesParent); err != nil {
			return nil, fmt.Errorf("storage root %q not permitted; caller (uid %d) may only provision %q or a directory it owns: %w", req.GetPath(), uid, want, err)
		}
		return s.ensureCallerOwnedStorageRoot(req)
	}

	gid, groupName, err := resolveQEMUGroupGID()
	if err != nil {
		return nil, err
	}

	// Shared parent: root-owned, world-traversable (0o755) so every per-user root
	// under it is reachable, but not writable by non-root. It holds only per-user
	// roots, so it needs no setgid.
	if err := ensureDir(libvirtImagesParent, 0, 0, 0o755); err != nil {
		return nil, fmt.Errorf("failed to prepare %s: %w", libvirtImagesParent, err)
	}
	// Per-user root: owned uid:qemu-group, setgid 0750.
	if err := ensureDir(want, uid, gid, storageRootMode); err != nil {
		return nil, fmt.Errorf("failed to prepare %s: %w", want, err)
	}
	// The shared "instances"/"base" subdirs, under which the unprivileged
	// client creates per-instance leaves, MUST be provisioned here, as root:
	// see sharedStorageSubdirs for why an unprivileged chmod can never make
	// (or keep) them setgid.
	for _, sub := range sharedStorageSubdirs {
		if err := ensureDir(filepath.Join(want, sub), uid, gid, storageRootMode); err != nil {
			return nil, fmt.Errorf("failed to prepare %s: %w", filepath.Join(want, sub), err)
		}
	}

	// regroup: after `abox migrate` relocated files (chowning them to the caller's
	// primary group), walk the caller's OWN subtree and restore the QEMU group +
	// modes so the VM process can read them. The walk root is always `want`
	// (derived from the peer uid above, never from the request), and it never
	// follows a symlink out of the subtree.
	if req.GetRegroup() {
		if err := regroupSubtree(want, uid, gid); err != nil {
			return nil, fmt.Errorf("failed to regroup %s: %w", want, err)
		}
	}

	logging.Audit("storage root ensured", "path", want, "uid", uid, "group", groupName, "gid", gid, "regroup", req.GetRegroup())
	return &rpc.Empty{}, nil
}

// ensureCallerOwnedStorageRoot handles EnsureStorageRoot for a user-configured
// storage root: it group-shares a directory the caller ALREADY OWNS with the
// QEMU runtime group. This grants the caller nothing it could not do itself if
// it were a group member — files created beneath inherit the group but never
// setgid (the kernel strips S_ISGID from a non-member's files), the owner is
// never changed, and QEMU only reads disks the caller names in its own domain.
// Regroup is refused: it chowns a whole subtree and is only used by `abox
// migrate`, which targets the default root.
func (s *EgressServer) ensureCallerOwnedStorageRoot(req *rpc.EnsureStorageRootReq) (*rpc.Empty, error) {
	uid, path := s.allowedUID, req.GetPath()
	if req.GetRegroup() {
		return nil, fmt.Errorf("regroup is only permitted for the default storage root, not %q", path)
	}
	gid, groupName, err := resolveQEMUGroupGID()
	if err != nil {
		return nil, err
	}
	if err := ensureCallerOwnedRoot(path, uid, gid); err != nil {
		return nil, err
	}
	if err := checkTraversable(filepath.Dir(path), gid, groupName); err != nil {
		return nil, err
	}
	logging.Audit("storage root ensured", "path", path, "uid", uid, "group", groupName, "gid", gid, "mode", "caller-owned")
	return &rpc.Empty{}, nil
}

// ensureCallerOwnedRoot converges a caller-owned directory to the storage-root
// group and mode, and provisions its sharedStorageSubdirs. Every mutation goes
// through an fd opened by openDirNoFollow and is preceded by an ownership check
// on that same fd, so the inode acted on is always one the caller owns:
// swapping a symlink anywhere in the path gains nothing. Subdirs are resolved
// relative to the root's fd, never by re-walking the path. The owner is never
// changed, except to hand the caller a subdir the helper itself just created.
func ensureCallerOwnedRoot(path string, uid, gid int) error {
	root, err := openDirNoFollow(unix.AT_FDCWD, path)
	if err != nil {
		return err
	}
	defer root.Close()
	st, err := requireOwnedBy(root, uid, false)
	if err != nil {
		return err
	}
	if err := requireDedicatedDir(root, st, gid); err != nil {
		return err
	}
	if err := convergeDir(root, -1, gid, storageRootMode); err != nil {
		return err
	}

	for _, sub := range sharedStorageSubdirs {
		if err := ensureCallerOwnedSubdir(root, sub, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// ensureCallerOwnedSubdir creates (if absent) and converges the shared subdir
// name directly under the already-verified root fd.
func ensureCallerOwnedSubdir(root *os.File, name string, uid, gid int) error {
	created := true
	if err := unix.Mkdirat(int(root.Fd()), name, uint32(storageRootMode.Perm())); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("failed to create %s: %w", filepath.Join(root.Name(), name), err)
		}
		created = false
	}
	dir, err := openDirNoFollow(int(root.Fd()), name)
	if err != nil {
		return err
	}
	defer dir.Close()
	st, err := requireOwnedBy(dir, uid, created)
	if err != nil {
		return err
	}
	owner := -1
	if int(st.Uid) != uid { // root-owned: the helper just created it
		owner = uid
	}
	return convergeDir(dir, owner, gid, storageRootMode)
}

// requireOwnedBy fstats dir and requires it to be owned by uid — or, when
// allowRoot is set (a directory the helper itself just created), by root.
func requireOwnedBy(dir *os.File, uid int, allowRoot bool) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return nil, fmt.Errorf("failed to stat %s: %w", dir.Name(), err)
	}
	if int(st.Uid) != uid && (!allowRoot || st.Uid != 0) {
		return nil, fmt.Errorf("storage directory %s is owned by uid %d, not the caller (uid %d); refusing to share it", dir.Name(), st.Uid, uid)
	}
	return &st, nil
}

// requireDedicatedDir refuses to convert a directory that is already in use
// for something else (e.g. a storage_dir pointed at $HOME or ~/.ssh), since the
// root is re-grouped and narrowed to 2750. A directory qualifies if it is
// already a storage root (setgid, QEMU group) or holds nothing but the shared
// storage subdirs. Call it only after requireOwnedBy, so the helper never lists
// (and so never discloses entries of) a directory the caller does not own.
func requireDedicatedDir(dir *os.File, st *unix.Stat_t, gid int) error {
	if int(st.Gid) == gid && st.Mode&unix.S_ISGID != 0 {
		return nil
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("failed to list %s: %w", dir.Name(), err)
	}
	for _, name := range names {
		if !slices.Contains(sharedStorageSubdirs, name) {
			return fmt.Errorf("storage directory %s is not empty (contains %q); use a new, dedicated directory for storage_dir", dir.Name(), name)
		}
	}
	return nil
}

// checkTraversable verifies the QEMU process can reach a storage root below
// dir: every directory from dir up to "/" must grant search (x) to others, or
// to the QEMU group when it is the directory's group. A directory carrying a
// POSIX ACL is accepted as-is, since its mode bits alone can't tell. This is a
// usability check, not a security boundary — it turns an opaque "Cannot access
// storage file" at `virsh start` into an actionable error at create time.
func checkTraversable(dir string, gid int, groupName string) error {
	for {
		var st unix.Stat_t
		if err := unix.Stat(dir, &st); err != nil {
			return fmt.Errorf("failed to stat %s: %w", dir, err)
		}
		ok := st.Mode&unix.S_IXOTH != 0 || (int(st.Gid) == gid && st.Mode&unix.S_IXGRP != 0)
		if !ok {
			if n, err := unix.Getxattr(dir, "system.posix_acl_access", nil); err == nil && n > 0 {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("the QEMU process (group %s) cannot traverse %s (mode %04o); grant search permission, e.g. `chmod o+x %s`", groupName, dir, st.Mode&0o7777, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// diskFileName is the basename of the writable CoW disk (see config.Paths.Disk
// in internal/config/config.go, kept in sync here for the same reason
// libvirtImagesParent is: the helper avoids importing config). regroupFile uses
// it to tell the writable disk apart from read-only sources (base image,
// cidata.iso), which need a different group mode — see regroupFile.
const diskFileName = "disk.qcow2"

// sharedStorageSubdirs are the two subdirectories the unprivileged client
// creates directly under the per-user storage root (see
// config.GetPathsWithStorage's diskDir/BaseImages in internal/config/config.go:
// "<storage root>/instances/<name>" and "<storage root>/base" — kept in sync
// here for the same reason libvirtImagesParent is). EnsureStorageRoot
// provisions THESE too (not just the root itself) because they must be setgid:
// an unprivileged chmod requesting S_ISGID is silently ignored by the kernel
// whenever the calling process is not a member of the target group (see
// chmod(2)) — true even when the bit is already correctly set and the chmod
// is a no-op "reassert". The calling user is never a member of the QEMU
// group, so ANY unprivileged chmod touching these dirs' setgid bit would
// corrupt it; provisioning them here, as root, is the only way they can ever
// be setgid. Once setgid+group is correct here, every leaf the unprivileged
// client creates underneath (e.g. "instances/<name>") inherits both
// automatically at mkdir time — no further chmod is needed or safe.
var sharedStorageSubdirs = []string{"instances", "base"}

// regroupSubtree walks the caller's own storage subtree rooted at root and, for
// every entry, chgrps it to gid and fixes its mode: directories get the setgid
// storage-root mode (so future children inherit the group), files get the
// group mode regroupFile assigns (the caller's owner bits are left intact). Runs
// as root in the helper, so it MUST NOT escape the subtree: it opens root as an
// os.Root (all subsequent operations are confined to
// it and refuse to traverse a symlink out of it) and applies chown/chmod through
// the root's path-confined methods. Symlinks are chowned in place (Lchown) and
// never chmod'd/followed.
//
// os.Root confines symlink and ".." traversal, but a HARDLINK is a real
// directory entry whose inode may also live outside the subtree — a chown/chmod
// through it would modify that out-of-tree inode. Since the subtree is
// caller-owned, an unprivileged caller could plant such a hardlink and turn this
// root-run op into an arbitrary-file chgrp/chmod primitive. So every regular file
// is opened O_NOFOLLOW and its link count checked via the fd; a file with
// nlink>1 is refused (files abox creates are always nlink==1), and the
// chown/chmod are applied through that same fd (no re-resolution, no TOCTOU).
func regroupSubtree(root string, uid, gid int) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	// r.FS() resolves paths within the root and does not follow symlinks out of
	// it, so the walk enumeration itself cannot escape the subtree.
	return fs.WalkDir(r.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Never dereference a symlink: chown it in place (Lchown) but do not chmod
		// (chmod would follow to the target, which may lie outside the subtree).
		if d.Type()&fs.ModeSymlink != 0 {
			return r.Lchown(rel, uid, gid)
		}
		if d.IsDir() {
			if err := r.Chown(rel, uid, gid); err != nil {
				return err
			}
			// Dirs: setgid 2750 so children keep inheriting the QEMU group.
			// (Directories cannot have extra hard links, so no nlink guard here.)
			return r.Chmod(rel, storageRootMode)
		}
		if d.Type().IsRegular() {
			return regroupFile(r, rel, uid, gid)
		}
		// Other (fifo/socket): chown in place, no mode change.
		return r.Chown(rel, uid, gid)
	})
}

// regroupFile chgrps a single regular file to gid and adds the group mode the
// QEMU process needs, operating through an O_NOFOLLOW fd so the nlink check and
// the chown/chmod all act on the same inode with no path re-resolution. It
// refuses a file with extra hard links (nlink>1) — see regroupSubtree for why.
//
// The group mode added depends on which file this is: the writable CoW disk
// (basename diskFileName) needs group-READ+WRITE — libvirt's own pre-start
// accessibility check runs before dynamic_ownership chowns the disk to the QEMU
// user, evaluating the file's pre-chown owner/mode, so only the group bits are
// available at that point and the writable layer needs W_OK (see diskFileMode
// in internal/backend/libvirt/disk.go). Read-only sources (base image,
// cidata.iso) only ever need group-read.
func regroupFile(r *os.Root, rel string, uid, gid int) error {
	f, err := r.OpenFile(rel, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Fail closed: without the link count we cannot rule out a hardlink to an
		// out-of-subtree inode, and this runs as root. (Never happens on Linux.)
		return fmt.Errorf("cannot determine link count of %s; refusing to regroup", rel)
	}
	if st.Nlink > 1 {
		return fmt.Errorf("refusing to regroup file with extra hard links %s (nlink=%d): possible attempt to redirect chown/chmod outside the storage subtree", rel, st.Nlink)
	}
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	groupMode := os.FileMode(0o040)
	if filepath.Base(rel) == diskFileName {
		groupMode = 0o060
	}
	// Preserve the owner bits, add the group mode; deny others.
	return f.Chmod((fi.Mode().Perm() & 0o700) | groupMode)
}

// ensureDir creates dir with the given owner and mode if absent, and converges an
// existing dir to them (idempotent). It is TOCTOU/symlink-safe: after Mkdir it
// opens the entry with O_NOFOLLOW|O_DIRECTORY (so a symlink planted at path is
// refused, not followed) and applies chown/chmod through the resulting fd
// (Fchown/Fchmod) — the mutations land on the opened directory, never on a target
// a swapped-in symlink might point at. This matters because the helper runs as
// root: chmod/chown by path would follow a symlink an unprivileged user could
// plant under the shared parent. Chmod is applied AFTER chown because Mkdir's
// mode is masked by umask (which can strip setgid) and chown clears setgid on
// some systems — so the explicit mode (including setgid) is set last.
func ensureDir(path string, uid, gid int, mode os.FileMode) error {
	if err := os.Mkdir(path, mode.Perm()); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	f, err := openDirNoFollow(unix.AT_FDCWD, path)
	if err != nil {
		return err
	}
	defer f.Close()
	return convergeDir(f, uid, gid, mode)
}

// openDirNoFollow opens name (relative to dirfd, or absolute with
// unix.AT_FDCWD) as a directory. O_NOFOLLOW: fail (ELOOP) if it is a symlink.
// O_DIRECTORY: fail (ENOTDIR) if it is not a directory. Either way a
// non-directory/symlink planted there is refused rather than operated on.
func openDirNoFollow(dirfd int, name string) (*os.File, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s safely: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// convergeDir applies owner (uid -1 leaves it unchanged), group and mode
// through the open fd. Chmod comes after chown so the explicit mode (including
// setgid) is set last — see ensureDir.
func convergeDir(f *os.File, uid, gid int, mode os.FileMode) error {
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	return f.Chmod(mode)
}

// resolveQEMUGroupGID resolves the group the QEMU process runs as, returning its
// gid and name. Preference order: (1) the uncommented `group = "..."` in
// qemu.conf, (2) the QEMU runtime user's own primary group (what libvirtd uses by
// default — this matches the observed runtime gid), (3) a known group name.
func resolveQEMUGroupGID() (int, string, error) {
	// (1) qemu.conf group.
	if name := valueFromQemuConf(qemuConfPath, "group"); name != "" {
		if gid, ok := lookupGID(name); ok {
			return gid, name, nil
		}
	}
	// (2) primary group of the resolved QEMU user.
	confUser := valueFromQemuConf(qemuConfPath, "user")
	for _, name := range append([]string{confUser}, knownQEMUUsers...) {
		if name == "" {
			continue
		}
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			if g, err := user.LookupGroupId(u.Gid); err == nil {
				return gid, g.Name, nil
			}
			return gid, u.Gid, nil
		}
	}
	// (3) known group names (shared with the helper's group-membership check).
	for _, name := range qemuDiskGroups {
		if gid, ok := lookupGID(name); ok {
			// kvm is a broad system group (many unrelated devices/users belong to
			// it); resolving via it means the storage tree is readable AND the
			// writable disk is WRITABLE by everyone in kvm, not just the QEMU
			// process (see diskFileMode in internal/backend/libvirt/disk.go: the
			// disk is 0660, group-read+write, not just group-read). Warn/audit so
			// the operator can pin the exact group. The narrower libvirt-qemu/qemu
			// names are fine.
			if name == "kvm" {
				logging.Warn("resolved QEMU runtime group via the broad 'kvm' fallback; the storage tree (including each instance's writable disk) will be group-readable AND group-writable by all kvm members. Set `group = \"...\"` in /etc/libvirt/qemu.conf to pin the exact QEMU group.", "group", name, "gid", gid)
			}
			return gid, name, nil
		}
	}
	return 0, "", errors.New("could not determine the QEMU runtime group (looked for a qemu.conf `group=`, the libvirt-qemu/qemu user's group, and libvirt-qemu/qemu/kvm); set `group = \"...\"` in /etc/libvirt/qemu.conf")
}

// lookupGID resolves a group name to its numeric gid.
func lookupGID(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}

// valueFromQemuConf returns the value of an uncommented `<key> = "..."` line in
// qemu.conf, or "" if absent/unreadable.
func valueFromQemuConf(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		return strings.Trim(strings.TrimSpace(v), `"`)
	}
	return ""
}
