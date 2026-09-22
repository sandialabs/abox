//go:build darwin

package vfkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/qemuimg"
	"github.com/sandialabs/abox/internal/timeout"
	"github.com/sandialabs/abox/internal/validation"
)

const (
	defaultTimeout = timeout.Default
	convertTimeout = 10 * time.Minute // qcow2↔raw conversion for large images

	// diskPerm / dirPerm: storage is user-owned and vfkit runs as the same
	// user, so the disk and base image need only owner read/write (0o600) and
	// created directories only owner rwx (0o700). No world-readable bits — there
	// is no separate hypervisor runtime user to grant access to (unlike libvirt).
	diskPerm = 0o600
	dirPerm  = 0o700
)

// instanceDiskPath returns the vfkit raw disk image path for an instance.
//
// vfkit (Apple Virtualization.framework) only supports raw disks, so the
// instance disk is a raw image and must NOT reuse paths.Disk, which is the
// libvirt "disk.qcow2". This mirrors the vmware backend, which derives its own
// path via vmrun.InstanceVMDKPath(paths.DiskDir) rather than reusing paths.Disk.
func instanceDiskPath(paths *config.Paths) string {
	return filepath.Join(paths.DiskDir, "disk.img")
}

// baseImagePath returns the raw base image path in the backend image store.
// The raw base catalog is populated by a later batch; EnsureBaseImage requires
// the ".raw" form here.
func baseImagePath(paths *config.Paths, base string) string {
	return filepath.Join(paths.BaseImages, base+".raw")
}

// DiskManager implements backend.DiskManager for macOS/vfkit.
//
// Uses raw disk images (required by vfkit/Apple Virtualization.framework) with
// APFS copy-on-write clones for space-efficient instance disks. All operations
// run unprivileged as the calling user: storage lives under a user-owned
// location and vfkit runs the VM as that same user, so there is no separate
// hypervisor runtime user and no privilege client anywhere in this backend.
type DiskManager struct{}

// Create creates the per-instance raw disk from the raw base image using an
// APFS clone (cp -c), then grows it to the requested size. The base image must
// already be raw (EnsureBaseImage installs it). Grow-only: the clone already
// contains the full base filesystem, GPT, and backup header, so truncating
// below its current size would corrupt the disk.
func (m *DiskManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if err := os.MkdirAll(paths.DiskDir, dirPerm); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	base := baseImagePath(paths, inst.Base)
	dst := instanceDiskPath(paths)

	// Shared lock on the base image: allows concurrent creates cloning from the
	// same base while blocking `abox base remove` (which takes an exclusive lock)
	// from deleting it mid-clone. Mirrors the libvirt backend; flock works on
	// Darwin via the unix build tag.
	unlock, lockErr := images.LockBaseImage(base, images.LockShared)
	if lockErr != nil {
		return fmt.Errorf("failed to lock base image: %w", lockErr)
	}
	defer unlock.Close()

	// APFS clone (instant copy-on-write; falls back to a regular copy on
	// non-APFS volumes).
	if err := cloneFile(ctx, base, dst); err != nil {
		return fmt.Errorf("failed to clone base image: %w", err)
	}

	diskBytes, err := validation.ParseDiskSize(inst.Disk)
	if err != nil {
		return fmt.Errorf("failed to parse disk size %q: %w", inst.Disk, err)
	}
	cloneInfo, err := os.Stat(dst)
	if err != nil {
		return fmt.Errorf("failed to stat cloned disk: %w", err)
	}
	if diskBytes < cloneInfo.Size() {
		return &errhint.ErrHint{
			Err: fmt.Errorf("requested disk size %s (%d bytes) is smaller than the %q base image (%d bytes)",
				inst.Disk, diskBytes, inst.Base, cloneInfo.Size()),
			Hint: fmt.Sprintf("Choose a disk size of at least %s.", humanizeBytes(cloneInfo.Size())),
		}
	}
	if diskBytes > cloneInfo.Size() {
		if err := os.Truncate(dst, diskBytes); err != nil {
			return fmt.Errorf("failed to resize disk to %s: %w", inst.Disk, err)
		}
	}

	if err := os.Chmod(dst, diskPerm); err != nil {
		return fmt.Errorf("failed to set disk permissions: %w", err)
	}
	return nil
}

// Delete removes an instance's disk directory.
func (m *DiskManager) Delete(_ context.Context, paths *config.Paths) error {
	if err := os.RemoveAll(paths.DiskDir); err != nil {
		return fmt.Errorf("failed to delete disk: %w", err)
	}
	return nil
}

// EnsureBaseImage ensures the raw base image exists in the backend image store.
// It APFS-clones the raw source from the user cache into the backend store,
// writing to a temp path and renaming atomically so a reader never observes a
// half-copied backend base. (Cross-process serialization of two concurrent
// creates is provided by the process-wide config.AcquireLock held across the
// whole create flow, not by this temp+rename.) Idempotent: returns immediately
// if the backend base already exists.
func (m *DiskManager) EnsureBaseImage(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	backendBase := baseImagePath(paths, inst.Base)
	if _, err := os.Stat(backendBase); err == nil {
		return nil
	}

	userBase := filepath.Join(paths.UserBaseImages, inst.Base+".raw")
	if _, err := os.Stat(userBase); err != nil {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("base image not found: %s", inst.Base),
			Hint: "Download with: abox base pull " + inst.Base,
		}
	}

	if err := os.MkdirAll(paths.BaseImages, dirPerm); err != nil {
		return fmt.Errorf("failed to create base images directory: %w", err)
	}

	tmp := backendBase + ".copying"
	logging.Debug("cloning base image into backend storage", "src", userBase, "dst", backendBase)
	if err := cloneFile(ctx, userBase, tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to clone base image into backend storage: %w", err)
	}
	if err := os.Chmod(tmp, diskPerm); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to set base image permissions: %w", err)
	}
	if err := os.Rename(tmp, backendBase); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to install base image: %w", err)
	}
	logging.Debug("base image installed into backend storage")
	return nil
}

// EnsureAccess re-asserts the calling user's access to an existing instance's
// disk (idempotent). On macOS vfkit runs the VM as the invoking user, who
// already owns the disk, so there is no separate runtime user to grant. This
// only re-asserts the owner-only mode on the disk if it exists — enough to
// satisfy the interface and repair a mode stripped by a remount/restore.
func (m *DiskManager) EnsureAccess(_ context.Context, _ *config.Instance, paths *config.Paths) error {
	dst := instanceDiskPath(paths)
	if _, err := os.Stat(dst); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat disk: %w", err)
	}
	if err := os.Chmod(dst, diskPerm); err != nil {
		return fmt.Errorf("failed to re-assert disk permissions: %w", err)
	}
	return nil
}

// Import imports an existing disk image into backend-managed storage as the
// instance's raw disk. The archived disk (from `abox export`) is qcow2 and is
// converted to raw for vfkit.
//
// A raw disk has no backing-file/CoW-delta concept, so a snapshot import is
// impossible: reject snapshot==true up front. A qcow2 carrying a backing-file
// reference (a snapshot/CoW-delta archive from the Linux backend's --snapshot
// export) also cannot be opened here — qemu-img would die on the absent backing
// file — so detect and reject it with actionable guidance.
func (m *DiskManager) Import(ctx context.Context, src string, _ *config.Instance, paths *config.Paths, snapshot bool) error {
	if snapshot {
		return &errhint.ErrHint{
			Err:  errors.New("the macOS/vfkit backend cannot import a snapshot: raw disks have no backing-file concept"),
			Hint: "Re-export the instance as a full archive (without --snapshot) and import that.",
		}
	}

	if err := os.MkdirAll(paths.DiskDir, dirPerm); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	// A qcow2 carrying a backing-file reference (a snapshot/CoW-delta archive from
	// the Linux backend's --snapshot export) cannot be opened here — qemu-img would
	// die on the absent backing file — so detect and reject it with actionable
	// guidance. The info probe reuses the default timeout.
	infoCtx, cancelInfo := context.WithTimeout(ctx, defaultTimeout)
	if err := qemuimg.RejectBackingFile(infoCtx, src,
		"the macOS/vfkit backend cannot import a snapshot disk (raw disks have no backing-file concept)",
		"Snapshot archives are not portable to macOS (raw disks have no backing-file concept).\n"+
			"Re-export the instance as a full archive (without --snapshot) and import that."); err != nil {
		cancelInfo()
		return err
	}
	cancelInfo()

	dst := instanceDiskPath(paths)
	convertCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()
	if err := qemuimg.ConvertToRaw(convertCtx, src, "qcow2", dst); err != nil {
		return fmt.Errorf("failed to convert imported disk to raw: %w", err)
	}
	if err := os.Chmod(dst, diskPerm); err != nil {
		return fmt.Errorf("failed to set disk permissions: %w", err)
	}
	return nil
}

// Export exports the instance's raw disk to a local destination as compressed
// qcow2 for a portable archive.
//
// The snapshot flag is rejected: a raw disk has no backing-file/CoW-delta
// layer, so a delta-only (snapshot) export is impossible — emitting a full
// image mislabeled as a snapshot would be a lie. A non-snapshot export is
// always self-contained.
func (m *DiskManager) Export(ctx context.Context, dst string, paths *config.Paths, snapshot bool) error {
	if snapshot {
		return &errhint.ErrHint{
			Err:  errors.New("the macOS/vfkit backend cannot export a snapshot: raw disks have no backing-file concept"),
			Hint: "Export without --snapshot to produce a full, self-contained archive.",
		}
	}
	convertCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()
	return qemuimg.ConvertToQcow2Compressed(convertCtx, instanceDiskPath(paths), "raw", dst)
}

// humanizeBytes formats a byte count as a rounded-up disk-size string (e.g.
// "4G") suitable for use as a --disk argument. It rounds up to the next whole
// gigabyte so the suggested size is always large enough.
func humanizeBytes(b int64) string {
	const gib = 1024 * 1024 * 1024
	g := max((b+gib-1)/gib, 1)
	return fmt.Sprintf("%dG", g)
}

// cloneFile creates an APFS copy-on-write clone of src at dst, falling back to
// a regular copy if APFS cloning is unsupported (e.g. a non-APFS volume).
func cloneFile(ctx context.Context, src, dst string) error {
	cloneCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(cloneCtx, "cp", "-c", src, dst)
	if _, err := cmd.CombinedOutput(); err != nil {
		os.Remove(dst) // clean up any partial file before falling back
		logging.Debug("APFS clone failed, falling back to regular copy", "error", err)
		return regularCopy(ctx, src, dst)
	}
	return nil
}

// regularCopy copies a file using cp (fallback for non-APFS volumes).
func regularCopy(ctx context.Context, src, dst string) error {
	copyCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()

	cmd := exec.CommandContext(copyCtx, "cp", src, dst)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("copy failed: %s: %w", string(output), err)
	}
	return nil
}
