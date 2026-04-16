//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/images"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

const (
	defaultTimeout = timeout.Default
	convertTimeout = 10 * time.Minute // qcow2→raw conversion for large images
)

// DiskManager implements backend.DiskManager for macOS.
// Uses raw disk images (required by vfkit/Apple Virtualization.framework)
// with APFS copy-on-write clones for space-efficient instance disks.
type DiskManager struct{}

// Create creates a new raw disk image from a base image using APFS cloning.
// The base image must already be in raw format (converted by EnsureBaseImage).
// Uses cp -c for instant APFS clone, then truncates to the requested size.
func (m *DiskManager) Create(ctx context.Context, _ rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error {
	// Ensure disk directory exists.
	// On macOS, storage is under ~/Library/Application Support/abox/ (user-owned),
	// so we create directories directly instead of through the privilege helper.
	if err := os.MkdirAll(paths.DiskDir, 0o755); err != nil { //nolint:gosec // user-owned storage directory
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	// Determine raw base image path
	baseImage := filepath.Join(paths.BaseImages, inst.Base+".raw")

	// Shared lock: allows concurrent creates, blocks during base remove
	unlock, lockErr := images.LockBaseImage(baseImage, syscall.LOCK_SH)
	if lockErr != nil {
		return fmt.Errorf("failed to lock base image: %w", lockErr)
	}
	defer unlock.Close()

	// APFS clone: instant copy-on-write at filesystem level.
	// Falls back to regular copy on non-APFS volumes.
	if err := cloneFile(ctx, baseImage, paths.Disk); err != nil {
		return fmt.Errorf("failed to clone base image: %w", err)
	}

	// Extend disk to requested size (base image may be smaller)
	diskBytes, err := parseDiskSize(inst.Disk)
	if err != nil {
		return fmt.Errorf("failed to parse disk size %q: %w", inst.Disk, err)
	}
	if err := os.Truncate(paths.Disk, diskBytes); err != nil {
		return fmt.Errorf("failed to resize disk to %s: %w", inst.Disk, err)
	}

	// Set permissions (644 matches libvirt backend; disk must be readable by vfkit)
	if err := os.Chmod(paths.Disk, 0o644); err != nil { //nolint:gosec // disk images need world-readable for VM access
		return fmt.Errorf("failed to set disk permissions: %w", err)
	}

	return nil
}

// Delete removes a disk image.
func (m *DiskManager) Delete(_ context.Context, _ rpc.PrivilegeClient, paths *config.Paths) error {
	if err := os.RemoveAll(paths.DiskDir); err != nil {
		return fmt.Errorf("failed to delete disk: %w", err)
	}
	return nil
}

// EnsureBaseImage ensures the base image exists in the backend's image store
// in raw format. Base images are downloaded as qcow2 and converted to raw
// once during this step. Subsequent calls are no-ops.
func (m *DiskManager) EnsureBaseImage(ctx context.Context, _ rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error {
	userBaseImage := filepath.Join(paths.UserBaseImages, inst.Base+".qcow2")
	backendBaseImage := filepath.Join(paths.BaseImages, inst.Base+".raw")

	// Check if raw base already exists in backend location
	if _, err := os.Stat(backendBaseImage); err == nil {
		return nil
	}

	// Check if qcow2 source exists in user cache
	if _, err := os.Stat(userBaseImage); err != nil {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("base image not found: %s", inst.Base),
			Hint: "Download with: abox base pull " + inst.Base,
		}
	}

	// Ensure base images directory exists (user-owned on macOS)
	if err := os.MkdirAll(paths.BaseImages, 0o755); err != nil { //nolint:gosec // user-owned storage directory
		return fmt.Errorf("failed to create base images directory: %w", err)
	}

	// Convert qcow2 → raw (one-time per base image).
	// Write to a temp file first, then rename atomically to avoid races
	// where concurrent creates could see a half-written base image.
	tempBase := backendBaseImage + ".converting"
	logging.Debug("converting base image to raw format", "src", userBaseImage, "dst", backendBaseImage)
	if err := convertQcow2ToRaw(ctx, userBaseImage, tempBase); err != nil {
		os.Remove(tempBase)
		return fmt.Errorf("failed to convert base image to raw: %w", err)
	}

	if err := os.Chmod(tempBase, 0o644); err != nil { //nolint:gosec // base images need world-readable for VM access
		os.Remove(tempBase)
		return fmt.Errorf("failed to set base image permissions: %w", err)
	}

	// Atomic rename — if another process raced us, one rename wins and
	// the other is a no-op (both produced the same content).
	if err := os.Rename(tempBase, backendBaseImage); err != nil {
		os.Remove(tempBase)
		return fmt.Errorf("failed to install converted base image: %w", err)
	}

	logging.Debug("base image converted to raw format successfully")
	return nil
}

// Import imports an existing disk image into backend-managed storage.
// The source disk (from an archive) is in qcow2 format and is converted
// to raw for use with vfkit.
func (m *DiskManager) Import(ctx context.Context, _ rpc.PrivilegeClient, src string, _ *config.Instance, paths *config.Paths, _ bool) error {
	// Ensure disk directory exists (user-owned on macOS)
	if err := os.MkdirAll(paths.DiskDir, 0o755); err != nil { //nolint:gosec // user-owned storage directory
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	// Convert imported qcow2 to raw
	// The snapshot parameter is ignored — raw disks are always self-contained
	// (no backing-file concept at the format level).
	if err := convertQcow2ToRaw(ctx, src, paths.Disk); err != nil {
		return fmt.Errorf("failed to convert imported disk to raw: %w", err)
	}

	return nil
}

// Export exports a disk image to a local destination path.
// Converts the raw disk to compressed qcow2 for portable archives.
// The snapshot parameter is ignored — raw disks are always self-contained.
func (m *DiskManager) Export(ctx context.Context, _ rpc.PrivilegeClient, dst string, paths *config.Paths, _ bool) error {
	return convertRawToQcow2(ctx, paths.Disk, dst)
}

// convertQcow2ToRaw converts a qcow2 disk image to raw format using qemu-img.
func convertQcow2ToRaw(ctx context.Context, src, dst string) error {
	convertCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()

	cmd := exec.CommandContext(convertCtx, "qemu-img", "convert", "-f", "qcow2", "-O", "raw", src, dst)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img convert (qcow2→raw) failed: %s: %w", string(output), err)
	}
	return nil
}

// convertRawToQcow2 converts a raw disk image to compressed qcow2 format.
func convertRawToQcow2(ctx context.Context, src, dst string) error {
	convertCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()

	cmd := exec.CommandContext(convertCtx, "qemu-img", "convert", "-c", "-f", "raw", "-O", "qcow2", src, dst)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img convert (raw→qcow2) failed: %s: %w", string(output), err)
	}
	return nil
}

// cloneFile creates an APFS copy-on-write clone of src at dst.
// Falls back to a regular copy if APFS cloning is not supported (e.g., non-APFS volume).
func cloneFile(ctx context.Context, src, dst string) error {
	cloneCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(cloneCtx, "cp", "-c", src, dst)
	if _, err := cmd.CombinedOutput(); err != nil {
		// Clean up any partial file before falling back
		os.Remove(dst)
		logging.Debug("APFS clone failed, falling back to regular copy", "error", err)
		return regularCopy(ctx, src, dst)
	}
	return nil
}

// regularCopy copies a file using standard I/O (fallback for non-APFS volumes).
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

// parseDiskSize parses a size string like "20G" into bytes.
func parseDiskSize(size string) (int64, error) {
	size = strings.TrimSpace(size)
	if len(size) < 2 {
		return 0, fmt.Errorf("invalid disk size: %s", size)
	}

	suffix := size[len(size)-1]
	numStr := size[:len(size)-1]

	var multiplier int64
	switch suffix {
	case 'K', 'k':
		multiplier = 1024
	case 'M', 'm':
		multiplier = 1024 * 1024
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("disk size must end with K, M, G, or T: %s", size)
	}

	value, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid disk size number: %s", size)
	}

	return value * multiplier, nil
}
