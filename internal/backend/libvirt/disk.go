//go:build linux

package libvirt

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	defaultTimeout  = timeout.Default
	copyFileTimeout = 5 * time.Minute // Large images need more time
)

// DiskManager implements backend.DiskManager for libvirt.
type DiskManager struct{}

// Create creates a new disk image from a base image using copy-on-write.
func (m *DiskManager) Create(ctx context.Context, client rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error {
	// Ensure disk directory exists
	mkdirCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	_, err := client.MkdirAll(mkdirCtx, &rpc.MkdirReq{
		Path: paths.DiskDir,
		Mode: "755",
	})
	if err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	// Determine base image path
	libvirtBaseImage := filepath.Join(paths.BaseImages, inst.Base+".qcow2")

	// Shared lock: allows concurrent creates, blocks during base remove
	unlock, lockErr := images.LockBaseImage(libvirtBaseImage, syscall.LOCK_SH)
	if lockErr != nil {
		return fmt.Errorf("failed to lock base image: %w", lockErr)
	}
	defer unlock.Close()

	// Create CoW disk from base via privileged helper
	createCtx, createCancel := context.WithTimeout(ctx, defaultTimeout)
	defer createCancel()

	_, err = client.QemuImgCreate(createCtx, &rpc.QemuImgReq{
		BackingFile: libvirtBaseImage,
		Output:      paths.Disk,
		Size:        inst.Disk,
	})
	if err != nil {
		return fmt.Errorf("failed to create disk: %w", err)
	}

	// Set permissions for libvirt access
	chmodCtx, chmodCancel := context.WithTimeout(ctx, defaultTimeout)
	defer chmodCancel()

	_, err = client.Chmod(chmodCtx, &rpc.ChmodReq{
		Path: paths.Disk,
		Mode: "644",
	})
	if err != nil {
		return fmt.Errorf("failed to set disk permissions: %w", err)
	}

	return nil
}

// Delete removes a disk image.
func (m *DiskManager) Delete(ctx context.Context, client rpc.PrivilegeClient, paths *config.Paths) error {
	deleteCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	_, err := client.RemoveAll(deleteCtx, &rpc.PathReq{Path: paths.DiskDir})
	if err != nil {
		return fmt.Errorf("failed to delete disk: %w", err)
	}
	return nil
}

// EnsureBaseImage ensures the base image exists in the libvirt image store.
// If the image is only in user cache, it copies it to the libvirt-accessible location.
func (m *DiskManager) EnsureBaseImage(ctx context.Context, client rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error {
	userBaseImage := filepath.Join(paths.UserBaseImages, inst.Base+".qcow2")
	libvirtBaseImage := filepath.Join(paths.BaseImages, inst.Base+".qcow2")

	// Check if base image exists in either location
	_, userErr := os.Stat(userBaseImage)
	_, libvirtErr := os.Stat(libvirtBaseImage)

	if userErr != nil && libvirtErr != nil {
		return &errhint.ErrHint{
			Err:  fmt.Errorf("base image not found: %s", inst.Base),
			Hint: "Download with: abox base pull " + inst.Base,
		}
	}

	// If already in libvirt location, nothing to do
	if libvirtErr == nil {
		return nil
	}

	// Copy from user cache to libvirt location
	logging.Debug("copying base image to libvirt directory")

	// Ensure base images directory exists
	mkdirCtx, mkdirCancel := context.WithTimeout(ctx, defaultTimeout)
	defer mkdirCancel()

	_, err := client.MkdirAll(mkdirCtx, &rpc.MkdirReq{
		Path: paths.BaseImages,
		Mode: "755",
	})
	if err != nil {
		return fmt.Errorf("failed to create base images directory: %w", err)
	}

	// Copy base image
	copyCtx, copyCancel := context.WithTimeout(ctx, copyFileTimeout)
	defer copyCancel()

	_, err = client.CopyFile(copyCtx, &rpc.CopyReq{
		Src: userBaseImage,
		Dst: libvirtBaseImage,
	})
	if err != nil {
		return fmt.Errorf("failed to copy base image: %w", err)
	}

	// Set permissions
	chmodCtx, chmodCancel := context.WithTimeout(ctx, defaultTimeout)
	defer chmodCancel()

	_, err = client.Chmod(chmodCtx, &rpc.ChmodReq{
		Path: libvirtBaseImage,
		Mode: "644",
	})
	if err != nil {
		return fmt.Errorf("failed to set base image permissions: %w", err)
	}

	logging.Debug("base image copied successfully")
	return nil
}

// Import imports an existing disk image into backend-managed storage.
// Creates the disk directory, copies the disk, and for snapshot imports,
// rebases the disk to the local base image.
func (m *DiskManager) Import(ctx context.Context, client rpc.PrivilegeClient, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error {
	// Ensure disk directory exists (normally done by Create)
	mkdirCtx, mkdirCancel := context.WithTimeout(ctx, defaultTimeout)
	defer mkdirCancel()

	if _, err := client.MkdirAll(mkdirCtx, &rpc.MkdirReq{
		Path: paths.DiskDir,
		Mode: "755",
	}); err != nil {
		return fmt.Errorf("failed to create disk directory: %w", err)
	}

	// Copy disk image
	copyCtx, copyCancel := context.WithTimeout(ctx, copyFileTimeout)
	defer copyCancel()

	if _, err := client.CopyFile(copyCtx, &rpc.CopyReq{
		Src: src,
		Dst: paths.Disk,
	}); err != nil {
		return fmt.Errorf("failed to copy disk: %w", err)
	}

	// Rebase snapshot to local base image
	if snapshot {
		baseImage := filepath.Join(paths.BaseImages, inst.Base+".qcow2")
		if err := rebaseDisk(ctx, paths.Disk, baseImage); err != nil {
			return fmt.Errorf("failed to rebase disk: %w", err)
		}
	}

	return nil
}

// Export exports a disk image to a local destination path.
// If snapshot is true, copies the raw CoW layer. Otherwise, flattens
// the disk by merging it with its backing file.
func (m *DiskManager) Export(ctx context.Context, _ rpc.PrivilegeClient, dst string, paths *config.Paths, snapshot bool) error {
	if snapshot {
		return copyDiskFile(paths.Disk, dst)
	}
	return flattenDisk(ctx, paths.Disk, dst)
}

// rebaseDisk rebases a CoW disk to a new backing file.
func rebaseDisk(ctx context.Context, disk, backingFile string) error {
	cmd := exec.CommandContext(ctx, "qemu-img", "rebase", "-u", "-b", backingFile, "-F", "qcow2", disk)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img rebase failed: %s: %w", string(output), err)
	}
	return nil
}

// flattenDisk flattens a CoW disk by merging it with its backing file.
func flattenDisk(ctx context.Context, src, dst string) error {
	cmd := exec.CommandContext(ctx, "qemu-img", "convert", "-c", "-f", "qcow2", "-O", "qcow2", src, dst)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img convert failed: %s: %w", string(output), err)
	}
	return nil
}

// copyDiskFile copies a disk file from src to dst.
func copyDiskFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
