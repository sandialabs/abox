//go:build linux

package libvirt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/fsutil"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/qemuimg"
	"github.com/sandialabs/abox/internal/sysutil"
	"github.com/sandialabs/abox/internal/timeout"
)

// Storage modes for the per-user libvirt storage tree. The tree lives outside
// $HOME under a root the privilege helper created owned by the caller and setgid
// to the QEMU runtime group (see the helper's EnsureStorageRoot). Because the
// root is setgid, every directory and file the calling user creates beneath it
// inherits that group, so the QEMU process reads/writes images by group
// membership — no ACLs and no $HOME traversal. The unprivileged create path only
// needs to chmod the group bits into place.
const (
	// storageDirMode: setgid (propagate the QEMU group to new entries), owner
	// rwx, group r-x (the VM process traverses + lists), nothing for others.
	storageDirMode = os.ModeSetgid | 0o750
	// diskFileMode: the writable CoW disk — owner rw, group r, nothing for others.
	// The disk is the VM's writable layer, but the group needs only READ here:
	// with libvirtd dynamic_ownership=1 (the default) libvirt chowns the disk to
	// the QEMU user at VM start, granting owner-write; group-write would widen
	// access to the whole QEMU group for no benefit. (If dynamic_ownership=0 the
	// disk must be group-writable — see docs/privilege-helper.md.)
	diskFileMode = 0o640
	// roFileMode: a read-only image/ISO (base backing file, cloud-init) — owner
	// rw, group r (the VM process reads it), nothing for others.
	roFileMode = 0o640
)

// DiskManager implements backend.DiskManager for libvirt.
//
// Per-instance disk operations (create/copy/import/qemu-img) run unprivileged as
// the calling user in the per-user storage tree. The ONE privileged step —
// provisioning that tree's root (owned by the caller, setgid to the QEMU group)
// — is delegated to the injected storageProvider, so the QEMU runtime user can
// reach the images via group membership without any ACLs.
type DiskManager struct {
	storageProvider backend.StorageEnforcerProvider
}

// ensureStorageRoot provisions the caller's per-user storage root via the
// privilege helper (idempotent). No-op when no provider is injected (e.g. unit
// tests using a temp storage dir), which keeps the disk paths unit-testable
// without a helper.
func (m *DiskManager) ensureStorageRoot(ctx context.Context) error {
	if m.storageProvider == nil {
		return nil
	}
	enforcer, err := m.storageProvider()
	if err != nil {
		return fmt.Errorf("failed to obtain storage provider: %w", err)
	}
	if err := enforcer.EnsureStorageRoot(ctx, config.LibvirtStorageDir(), false); err != nil {
		return fmt.Errorf("failed to prepare storage root: %w", err)
	}
	return nil
}

// prepareDir creates dir (and parents) under the storage root and sets the
// storage directory mode on both dir AND its immediate parent. The QEMU group is
// inherited from the setgid root, so only the mode (incl. setgid) is set here —
// no chgrp (which the unprivileged caller could not perform anyway).
//
// Both the leaf and its parent are chmod'd because MkdirAll creates intermediate
// dirs (e.g. the shared "instances"/"base" level between the storage root and
// this leaf) with a umask-masked mode that can lack setgid; without fixing the
// parent, a directory created there by a different code path could fail to
// propagate the QEMU group. Making prepareDir converge the parent too keeps the
// tree's modes deterministic regardless of creation order.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, storageDirMode.Perm()); err != nil {
		return err
	}
	if err := os.Chmod(dir, storageDirMode); err != nil {
		return err
	}
	// Converge the immediate parent (the shared instances/base level) too. Best
	// effort: the storage root itself is helper-owned setgid and above the tree
	// this caller manages, so a chmod failure there is not fatal to this op.
	parent := filepath.Dir(dir)
	if err := os.Chmod(parent, storageDirMode); err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}

// lstatNoSymlink stats path without following symlinks and fails closed if it is
// one. A plain os.Chmod follows symlinks, so a symlink planted at an image path
// (disk/base/ISO) would redirect the mode change onto its target. These paths
// live in the caller's own storage tree, but guarding here keeps the
// group-readable modes from ever being applied through a link. Shared by the
// chmod* helpers so both enforce the same no-symlink invariant.
func lstatNoSymlink(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to chmod symlink %s", path)
	}
	return info, nil
}

// chmodNoFollow chmods path only if it is a regular file, refusing symlinks.
//
// mode is currently 0640 at every call site (diskFileMode == roFileMode), but the
// two are distinct consts on purpose: a dynamic_ownership=0 host needs the disk
// group-writable (see the diskFileMode comment), which would give the disk a
// different mode. Keeping the parameter preserves that per-file intent.
//
//nolint:unparam // see above — disk vs read-only mode intentionally distinct
func chmodNoFollow(path string, mode os.FileMode) error {
	if _, err := lstatNoSymlink(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// chmodIfOwned chmods a regular file to mode, but only when the calling user
// still owns it; otherwise it is a no-op (logged at debug).
//
// This exists for the every-boot EnsureAccess path. After a prior VM start,
// libvirtd dynamic_ownership=1 chowns disk/CDROM sources to the QEMU runtime
// user, and readonly sources (the base backing file, the cloud-init ISO) are NOT
// chowned back on shutdown (libvirt only restores writable, exclusive images).
// The unprivileged caller then can neither chmod such a file (chmod by a
// non-owner is EPERM) nor needs to: libvirt left the MODE intact and the QEMU
// process reaches the file as its new owner. Treating that as fatal would break
// every restart, so we skip it. The legitimate repair case — a file the caller
// still owns whose mode drifted (remount without acl, restore-from-backup) — is
// unaffected. A file the caller lost that ALSO lost its mode/group is out of
// scope here and must be repaired by the privileged helper (`abox migrate`), as
// EnsureAccess's doc comment notes. Symlinks are refused (fail closed) like
// chmodNoFollow. mode is 0640 at every call site today, but diskFileMode and
// roFileMode are intentionally distinct consts (see chmodNoFollow) and may diverge.
//
//nolint:unparam // mode intentionally kept per-file; see chmodNoFollow
func chmodIfOwned(path string, mode os.FileMode) error {
	info, err := lstatNoSymlink(path)
	if err != nil {
		return err
	}
	if uid, _, ok := sysutil.FileOwner(info); !ok || uid != os.Getuid() {
		logging.Debug("skipping chmod of file not owned by caller (libvirt dynamic ownership)", "path", path)
		return nil
	}
	return os.Chmod(path, mode)
}

// Create creates a new disk image from a base image using copy-on-write.
func (m *DiskManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if err := m.ensureStorageRoot(ctx); err != nil {
		return err
	}
	// Ensure disk directory exists (setgid; group inherited from the root so the
	// QEMU process can traverse+read).
	if err := prepareDir(paths.DiskDir); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	// Determine base image path
	baseImage := filepath.Join(paths.BaseImages, inst.Base+".qcow2")

	// Shared lock: allows concurrent creates, blocks during base remove
	unlock, lockErr := images.LockBaseImage(baseImage, images.LockShared)
	if lockErr != nil {
		return fmt.Errorf("failed to lock base image: %w", lockErr)
	}
	defer unlock.Close()

	// Create CoW disk from base
	createCtx, createCancel := context.WithTimeout(ctx, timeout.Default)
	defer createCancel()

	if err := qemuimg.Create(createCtx, baseImage, paths.Disk, inst.Disk); err != nil {
		return fmt.Errorf("failed to create disk: %w", err)
	}

	// The disk inherits the QEMU group from the setgid dir; give the group read so
	// the VM process can reach the CoW layer (libvirtd dynamic ownership grants
	// owner-write at VM start), and deny others.
	if err := chmodNoFollow(paths.Disk, diskFileMode); err != nil {
		return fmt.Errorf("failed to set disk permissions: %w", err)
	}

	return nil
}

// Delete removes a disk image.
func (m *DiskManager) Delete(ctx context.Context, paths *config.Paths) error {
	// Invariant: DiskDir = <validated storage>/instances/<name>, and
	// config.validateStorageDir guarantees the storage dir is absolute and free of
	// ".." traversal — so this RemoveAll cannot escape the instance's own storage
	// tree.
	if err := os.RemoveAll(paths.DiskDir); err != nil {
		return fmt.Errorf("failed to delete disk: %w", err)
	}
	return nil
}

// EnsureBaseImage ensures the base image exists in the backend image store.
// If the image is only in user cache, it copies it to the storage location.
func (m *DiskManager) EnsureBaseImage(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if err := m.ensureStorageRoot(ctx); err != nil {
		return err
	}
	storedBaseImage := filepath.Join(paths.BaseImages, inst.Base+".qcow2")
	userBaseImage := filepath.Join(paths.UserBaseImages, inst.Base+".qcow2")

	// Common case: already in storage AND owned by the calling user. Repair the
	// mode (idempotent; chmod to group-readable also fixes an image left
	// non-owner-readable or 0o644 by an older version) without touching the cache.
	if info, err := os.Stat(storedBaseImage); err == nil {
		if uid, _, ok := sysutil.FileOwner(info); ok && uid == os.Getuid() {
			return chmodNoFollow(storedBaseImage, roFileMode)
		}
		// Foreign-owned stored base (e.g. a root-owned artifact left by an older
		// version): we cannot chmod it, so both the base lock (LockBaseImage's
		// os.Open) and QEMU fail with an opaque "permission denied". Self-heal by
		// re-copying from the user cache below; if the cache is gone, surface an
		// actionable error instead.
		if _, err := os.Stat(userBaseImage); err != nil {
			return &errhint.ErrHint{
				Err:  fmt.Errorf("stored base image %s is not owned by you and cannot be repaired", storedBaseImage),
				Hint: "remove the stale image (may need sudo) and re-download: abox base rm " + inst.Base + " && abox base pull " + inst.Base,
			}
		}
		logging.Debug("stored base image not owned by caller; repairing from user cache")
	} else if _, err := os.Stat(userBaseImage); err != nil {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("base image not found: %s", inst.Base),
			Hint: "Download with: abox base pull " + inst.Base,
		}
	}

	// Copy from user cache to storage location.
	logging.Debug("copying base image to storage directory")

	if err := prepareDir(paths.BaseImages); err != nil {
		return fmt.Errorf("failed to create base images directory: %w", err)
	}

	if err := fsutil.CopyFile(userBaseImage, storedBaseImage); err != nil {
		return fmt.Errorf("failed to copy base image: %w", err)
	}

	// The base is the CoW disk's read-only backing file; the QEMU group (inherited
	// from the setgid dir) needs read.
	if err := chmodNoFollow(storedBaseImage, roFileMode); err != nil {
		return fmt.Errorf("failed to set base image permissions: %w", err)
	}

	logging.Debug("base image copied successfully")
	return nil
}

// EnsureAccess re-asserts the QEMU runtime user's access to an existing
// instance's disk, base image, and cloud-init ISO before VM boot (idempotent):
// it ensures the per-user storage root exists (provisioning it via the helper if
// absent) and re-applies the group-readable MODES on the storage dir and the
// image files.
//
// This is the unprivileged every-boot path, so it only fixes modes — it does NOT
// chgrp the files (an unprivileged caller cannot). If a restore-from-backup
// dropped the QEMU GROUP off the files (not just their modes), that must be
// repaired by the privileged helper's regroup step (`abox migrate` after a
// relocation), not here.
func (m *DiskManager) EnsureAccess(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if err := m.ensureStorageRoot(ctx); err != nil {
		return err
	}
	// Re-assert the setgid mode on the instance dir (owned by the caller — libvirt
	// chowns files, not dirs — so this always succeeds).
	if err := os.Chmod(paths.DiskDir, storageDirMode); err != nil {
		return fmt.Errorf("failed to set disk directory permissions: %w", err)
	}
	// Per-file modes are re-asserted only for files the caller still owns: a prior
	// boot may have left a readonly source (base image, ISO) owned by the QEMU user
	// via libvirt dynamic ownership, which we cannot and need not chmod (see
	// chmodIfOwned). The writable disk is normally chowned back on shutdown, so its
	// chmod usually applies; guarding it too keeps the path robust if it was not.
	if err := chmodIfOwned(paths.Disk, diskFileMode); err != nil {
		return fmt.Errorf("failed to set disk permissions: %w", err)
	}
	baseImage := filepath.Join(paths.BaseImages, inst.Base+".qcow2")
	if _, err := os.Stat(baseImage); err == nil {
		if err := chmodIfOwned(baseImage, roFileMode); err != nil {
			return fmt.Errorf("failed to set base image permissions: %w", err)
		}
	}
	if _, err := os.Stat(paths.CloudInitISO); err == nil {
		if err := chmodIfOwned(paths.CloudInitISO, roFileMode); err != nil {
			return fmt.Errorf("failed to set cloud-init ISO permissions: %w", err)
		}
	}
	return nil
}

// Import imports an existing disk image into backend-managed storage.
// Creates the disk directory, copies the disk, and for snapshot imports,
// rebases the disk to the local base image.
func (m *DiskManager) Import(ctx context.Context, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error {
	if err := m.ensureStorageRoot(ctx); err != nil {
		return err
	}
	// Ensure disk directory exists (setgid; group inherited from the root).
	if err := prepareDir(paths.DiskDir); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	// Reject any external reference the imported disk would keep and libvirt/QEMU
	// would follow at boot as the (more-privileged) libvirt-qemu runtime user. A
	// snapshot import legitimately carries a backing-file pointer — rebased onto the
	// local base below — so tolerate that here; but a qcow2 external data-file
	// pointer is an independent host-path reference that rebase does NOT touch, so it
	// is rejected in BOTH modes. This runs in snapshot mode too because
	// manifest.Snapshot is attacker-controlled and Rebase (-u) only rewrites the
	// backing pointer, not a data-file.
	if err := qemuimg.RejectExternalReferences(ctx, src,
		"an imported disk must be self-contained",
		"flatten the image first: qemu-img convert -O qcow2 <src> <flat.qcow2>",
		qemuimg.ExternalRefOpts{AllowBackingFile: snapshot}); err != nil {
		return err
	}

	if snapshot {
		if err := m.importSnapshotDisk(ctx, src, inst, paths); err != nil {
			return err
		}
	} else {
		// A non-snapshot import must be self-contained: convert (flatten) rather than
		// byte-copy, so the stored disk provably carries no backing- or data-file
		// pointer regardless of who opens it later. The guard above already rejected
		// a data-file, so this convert cannot read a host file through one.
		if err := qemuimg.Convert(ctx, src, paths.Disk, false); err != nil {
			return fmt.Errorf("failed to import disk: %w", err)
		}
	}

	// The imported disk is the writable CoW layer; give the QEMU group (inherited
	// from the setgid dir) read (dynamic ownership grants owner-write at VM start)
	// and deny others.
	if err := chmodNoFollow(paths.Disk, diskFileMode); err != nil {
		return fmt.Errorf("failed to set disk permissions: %w", err)
	}
	return nil
}

// importSnapshotDisk imports a snapshot (CoW delta) disk: because it is backed by
// the local base image it cannot be flattened, so the delta is copied verbatim
// and its backing pointer repointed at the local base. The imported disk reads
// through that base at runtime, so QEMU needs read access to it (it is not granted
// via EnsureBaseImage on this path).
func (m *DiskManager) importSnapshotDisk(ctx context.Context, src string, inst *config.Instance, paths *config.Paths) error {
	if err := fsutil.CopyFile(src, paths.Disk); err != nil {
		return fmt.Errorf("failed to copy disk: %w", err)
	}
	baseImage := filepath.Join(paths.BaseImages, inst.Base+".qcow2")
	if err := qemuimg.Rebase(ctx, paths.Disk, baseImage); err != nil {
		return fmt.Errorf("failed to rebase disk: %w", err)
	}
	// The base may legitimately be absent on this path; only fix its mode if present.
	if _, err := os.Stat(baseImage); err == nil {
		if err := chmodNoFollow(baseImage, roFileMode); err != nil {
			return fmt.Errorf("failed to set base image permissions: %w", err)
		}
	}
	return nil
}

// Export exports a disk image to a local destination path.
// If snapshot is true, copies the raw CoW layer. Otherwise, flattens
// the disk by merging it with its backing file.
func (m *DiskManager) Export(ctx context.Context, dst string, paths *config.Paths, snapshot bool) error {
	if snapshot {
		return fsutil.CopyFile(paths.Disk, dst)
	}
	// Flatten: merge the CoW layer with its backing file into a standalone,
	// compressed qcow2.
	return qemuimg.Convert(ctx, paths.Disk, dst, true)
}

// Disk copying is handled by fsutil.CopyFile (reflink fast path + buffered
// fallback, with a regular-file guard).
