package vmware

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/fsutil"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/qemuimg"
	"github.com/sandialabs/abox/internal/vmrun"
)

// DiskManager implements backend.DiskManager for VMware.
//
// All operations run unprivileged as the calling user. Unlike libvirt (whose
// QEMU process runs as a separate libvirt-qemu/qemu user needing ACLs), VMware
// Workstation/Fusion runs guest VMs as the invoking user, so no ACL/ownership
// grants are needed — the files the user creates here are already readable and
// writable by the process that will run the VM. This is why there is no
// group-ownership/ACL grant step below (unlike libvirt, which provisions a
// setgid storage root via EnsureStorageRoot so its separate QEMU user can read
// the images).
//
// VMware disk-level copy-on-write children require the VDDK or VM-level linked
// cloning, neither of which is available portably via the CLI. So the
// per-instance disk is a full, standalone COPY of the base VMDK: no parent
// dependency, correct on every host. The disk-space cost is accepted for
// Phase 1; a VM-level `vmrun clone --linked` is a later optimization. On
// reflink-capable filesystems (btrfs/xfs) the copy is near-instant and
// space-efficient anyway via fsutil.CopyFile's reflink fast path.
//
// This package is portable (no OS build tag): it avoids syscall flock,
// golang.org/x/sys, and images.LockBaseImage. Concurrency safety on the shared
// base image is provided by an atomic write-to-temp + os.Rename instead of a
// shared flock.
type DiskManager struct{}

// Create creates the per-instance disk as a full, standalone copy of the base
// VMDK.
func (m *DiskManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	base := vmrun.BaseVMDKPath(paths.BaseImages, inst.Base)
	dst := vmrun.InstanceVMDKPath(paths.DiskDir)

	// Full standalone copy (reflink fast path where supported). No ACL step:
	// VMware runs the VM as the invoking user, who already owns these files.
	if err := fsutil.CopyFile(base, dst); err != nil {
		return fmt.Errorf("failed to create disk: %w", err)
	}
	return nil
}

// Delete removes an instance's disk directory. ctx is accepted for interface
// conformance but unused: this is a local filesystem removal with nothing to
// cancel or time out.
func (m *DiskManager) Delete(ctx context.Context, paths *config.Paths) error {
	if err := os.RemoveAll(paths.DiskDir); err != nil {
		return fmt.Errorf("failed to delete disk: %w", err)
	}
	return nil
}

// EnsureBaseImage ensures the base VMDK exists in the backend image store,
// converting it from the qcow2 base if needed. Idempotent: if the base VMDK
// already exists it returns immediately (cached), so it does not re-convert.
func (m *DiskManager) EnsureBaseImage(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	baseVMDK := vmrun.BaseVMDKPath(paths.BaseImages, inst.Base)

	// Common case: already converted and cached.
	if _, err := os.Stat(baseVMDK); err == nil {
		return nil
	}

	// Locate the source base image: prefer the backend store, fall back to the
	// user cache (mirrors libvirt's fallback), otherwise hint the user to pull it.
	// The on-disk extension is platform-dependent (qcow2 on Linux, raw on macOS
	// where `abox base pull` writes raw), so probe both; the conversion below pins
	// the source format from the matched extension.
	src := findBaseImageSource(paths, inst.Base)
	if src == "" {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("base image not found: %s", inst.Base),
			Hint: "Download with: abox base pull " + inst.Base,
		}
	}

	logging.Debug("converting base image to vmdk", "base", inst.Base, "src", src, "dst", baseVMDK)

	if err := os.MkdirAll(paths.BaseImages, 0o700); err != nil {
		return fmt.Errorf("failed to create base images directory: %w", err)
	}

	// Convert into a temp file in the SAME directory, then rename into place.
	// The rename is atomic on POSIX and Windows (same dir), so concurrent
	// creates never observe a partial base VMDK — a portable substitute for
	// libvirt's flock around the base image.
	tmp, err := os.CreateTemp(paths.BaseImages, inst.Base+".vmdk.tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp base image: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	// Best-effort cleanup if we fail before the rename (no-op after a successful
	// rename, since the temp path no longer exists).
	defer os.Remove(tmpPath)

	// Pin the source format from the on-disk extension (never auto-probe an
	// untrusted image): qcow2 on Linux, raw on macOS.
	srcFormat := qemuimg.FormatForExt(filepath.Ext(src))
	if err := qemuimg.ConvertToVMDKFrom(ctx, src, srcFormat, tmpPath); err != nil {
		return fmt.Errorf("failed to convert base image to vmdk: %w", err)
	}

	if err := os.Rename(tmpPath, baseVMDK); err != nil {
		return fmt.Errorf("failed to finalize base image: %w", err)
	}
	logging.Debug("base image converted successfully", "base", inst.Base)
	return nil
}

// findBaseImageSource locates a downloaded base image for the given base name,
// preferring the backend store over the user download cache and probing every
// platform base-image extension (qcow2 on Linux, raw on macOS). It returns the
// first path that exists, or "" if none is found. The caller pins the qemu-img
// source format from the returned path's extension (see qemuimg.FormatForExt).
func findBaseImageSource(paths *config.Paths, base string) string {
	dirs := []string{paths.BaseImages, paths.UserBaseImages}
	for _, dir := range dirs {
		for _, ext := range config.BaseImageExts() {
			p := filepath.Join(dir, base+ext)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// EnsureAccess is a no-op for VMware. VMware Workstation/Fusion runs the VM as
// the invoking user, who already owns the disk, base, and cloud-init ISO, so
// there is no separate runtime user whose access must be (re-)granted — unlike
// libvirt, which re-asserts ACLs for the libvirt-qemu/qemu user here.
func (m *DiskManager) EnsureAccess(ctx context.Context, inst *config.Instance, paths *config.Paths) error {
	return nil
}

// Import imports an existing disk image into backend-managed storage as the
// instance disk.
//
// VMware backend disks are always standalone (a full copy — see the DiskManager
// doc), so there is no delta/backing layer and no rebase step, unlike libvirt's
// snapshot import. Both import modes therefore behave identically: the source is
// copied into the instance disk (converting qcow2->vmdk when the input is
// qcow2). The `snapshot` flag is accepted for interface parity but changes
// nothing here — the imported bytes are never discarded.
//
// Security: the source is validated by CONTENT (not filename) before it is
// trusted. A qcow2/qed/etc. carrying a backing-file pointer is rejected (as
// libvirt does), and a VMDK naming a parent or using an absolute/escaping extent
// path is rejected — otherwise the imported disk would keep an attacker-chosen
// pointer that the hypervisor would follow at boot.
func (m *DiskManager) Import(ctx context.Context, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error {
	_ = snapshot // VMware disks are standalone; both modes copy src (see doc).

	if err := os.MkdirAll(paths.DiskDir, 0o700); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	dst := vmrun.InstanceVMDKPath(paths.DiskDir)

	// Validate the untrusted source is self-contained and detect its format by
	// CONTENT (not filename). This shared guard rejects a child/linked VMDK, a VMDK
	// with an absolute/escaping extent path, and any image carrying a backing-file
	// pointer — before qemu-img is invoked.
	format, err := vmrun.InspectImportSource(ctx, src)
	if err != nil {
		return err
	}
	logging.Debug("importing disk", "src", src, "detected_format", format)

	if format == "vmdk" {
		// Already VMware's format and validated self-contained. Convert (flatten to a
		// single monolithicSparse VMDK) rather than copying verbatim, so no extent
		// reference survives into the stored disk; the convert pins -f vmdk so qemu-img
		// does not re-probe the untrusted source (see qemuimg.ConvertVMDKToVMDK).
		if err := qemuimg.ConvertVMDKToVMDK(ctx, src, dst); err != nil {
			return fmt.Errorf("failed to convert import vmdk: %w", err)
		}
		return nil
	}

	// ConvertToVMDK hardcodes `-f qcow2`, so only a qcow2 source can be converted
	// here. Reject any other qemu-native format (raw, qed, etc.) with a clear hint
	// rather than passing it to a converter that would misinterpret its bytes.
	// (base import has no such allowlist, so this gate lives in the backend.)
	if format != "qcow2" {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("import image format %q is not supported; only qcow2 or a self-contained VMDK can be imported", format),
			Hint: "convert the source to qcow2 (qemu-img convert -O qcow2 <src> <out.qcow2>) or supply a self-contained VMDK",
		}
	}
	if err := qemuimg.ConvertToVMDK(ctx, src, dst); err != nil {
		return fmt.Errorf("failed to convert import image to vmdk: %w", err)
	}
	return nil
}

// Export exports the instance disk to a local destination path.
func (m *DiskManager) Export(ctx context.Context, dst string, paths *config.Paths, snapshot bool) error {
	src := vmrun.InstanceVMDKPath(paths.DiskDir)
	if snapshot {
		// Copy the instance disk verbatim.
		return fsutil.CopyFile(src, dst)
	}
	// Produce a standalone image. The target format is chosen by the destination
	// FILE EXTENSION — a ".qcow2" dst yields a self-contained qcow2, anything else a
	// self-contained (monolithicSparse) VMDK, the common case for a VMware disk.
	// Extension (not content) is correct here: dst does not exist yet, and the
	// source disk is already trusted, so this is a format-choice convenience, not a
	// security decision (unlike Import, which inspects untrusted input by content).
	if filepath.Ext(dst) == ".qcow2" {
		return qemuimg.ConvertVMDKToQcow2(ctx, src, dst)
	}
	return qemuimg.FlattenVMDK(ctx, src, dst)
}
