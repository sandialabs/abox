//go:build darwin

package vfkit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
)

// newDiskTestPaths returns a *config.Paths with the disk/base fields pointed at
// hermetic temp dirs, so the disk provisioner touches nothing outside the test.
func newDiskTestPaths(t *testing.T) *config.Paths {
	t.Helper()
	storage := t.TempDir()
	user := t.TempDir()
	return &config.Paths{
		UserBaseImages: filepath.Join(user, "base"),
		BaseImages:     filepath.Join(storage, "base"),
		DiskDir:        filepath.Join(storage, "instances", "dev"),
	}
}

// writeFakeImage writes an n-byte file at path (creating parent dirs). Used to
// stand in for a raw base/disk image so Create/EnsureBaseImage have real bytes to
// clone with the same `cp` the code uses.
func writeFakeImage(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDiskCreate exercises the data-correctness branches of Create: the
// grow-only truncate, the owner-only mode, and the size-too-small guard.
func TestDiskCreate(t *testing.T) {
	m := &DiskManager{}
	ctx := context.Background()

	t.Run("clones base and grows to requested size with owner-only mode", func(t *testing.T) {
		paths := newDiskTestPaths(t)
		writeFakeImage(t, baseImagePath(paths, "ubuntu"), 1024) // 1 KiB base
		inst := &config.Instance{Base: "ubuntu", Disk: "8K"}    // grow to 8 KiB

		if err := m.Create(ctx, inst, paths); err != nil {
			t.Fatalf("Create: %v", err)
		}
		info, err := os.Stat(instanceDiskPath(paths))
		if err != nil {
			t.Fatalf("stat disk: %v", err)
		}
		if info.Size() != 8*1024 {
			t.Errorf("disk size = %d, want %d", info.Size(), 8*1024)
		}
		if info.Mode().Perm() != diskPerm {
			t.Errorf("disk mode = %o, want %o", info.Mode().Perm(), diskPerm)
		}
	})

	t.Run("rejects a requested size smaller than the base with an ErrHint", func(t *testing.T) {
		paths := newDiskTestPaths(t)
		writeFakeImage(t, baseImagePath(paths, "ubuntu"), 4096) // 4 KiB base
		inst := &config.Instance{Base: "ubuntu", Disk: "1K"}    // smaller than base

		err := m.Create(ctx, inst, paths)
		if err == nil {
			t.Fatal("expected an error when the requested disk is smaller than the base")
		}
		var hint *errhint.ErrHint
		if !errors.As(err, &hint) {
			t.Fatalf("expected *errhint.ErrHint, got %T: %v", err, err)
		}
		if hint.Hint == "" {
			t.Error("expected a non-empty remediation hint")
		}
	})
}

// TestDiskEnsureBaseImage covers the atomic install from the user cache, the
// idempotent no-op, and the missing-base hint.
func TestDiskEnsureBaseImage(t *testing.T) {
	m := &DiskManager{}
	ctx := context.Background()

	t.Run("installs from the user cache with owner-only mode and no temp leftover", func(t *testing.T) {
		paths := newDiskTestPaths(t)
		writeFakeImage(t, filepath.Join(paths.UserBaseImages, "ubuntu.raw"), 2048)
		inst := &config.Instance{Base: "ubuntu"}

		if err := m.EnsureBaseImage(ctx, inst, paths); err != nil {
			t.Fatalf("EnsureBaseImage: %v", err)
		}
		info, err := os.Stat(baseImagePath(paths, "ubuntu"))
		if err != nil {
			t.Fatalf("stat backend base: %v", err)
		}
		if info.Mode().Perm() != diskPerm {
			t.Errorf("base mode = %o, want %o", info.Mode().Perm(), diskPerm)
		}
		if _, err := os.Stat(baseImagePath(paths, "ubuntu") + ".copying"); !os.IsNotExist(err) {
			t.Error("temporary .copying file should not remain after an atomic install")
		}
	})

	t.Run("is a no-op when the backend base already exists", func(t *testing.T) {
		paths := newDiskTestPaths(t)
		writeFakeImage(t, baseImagePath(paths, "ubuntu"), 4096)
		inst := &config.Instance{Base: "ubuntu"}

		if err := m.EnsureBaseImage(ctx, inst, paths); err != nil {
			t.Fatalf("EnsureBaseImage (idempotent): %v", err)
		}
		info, _ := os.Stat(baseImagePath(paths, "ubuntu"))
		if info.Size() != 4096 {
			t.Errorf("existing backend base was modified: size = %d, want 4096", info.Size())
		}
	})

	t.Run("returns an ErrHint when the base is not in the user cache", func(t *testing.T) {
		paths := newDiskTestPaths(t)
		err := m.EnsureBaseImage(ctx, &config.Instance{Base: "ubuntu"}, paths)
		if err == nil {
			t.Fatal("expected an error for a missing base image")
		}
		var hint *errhint.ErrHint
		if !errors.As(err, &hint) {
			t.Fatalf("expected *errhint.ErrHint, got %T: %v", err, err)
		}
	})
}

// TestDiskEnsureAccess covers the mode repair and the disk-absent no-op.
func TestDiskEnsureAccess(t *testing.T) {
	m := &DiskManager{}
	ctx := context.Background()

	t.Run("no-op when the disk does not exist", func(t *testing.T) {
		paths := newDiskTestPaths(t)
		if err := m.EnsureAccess(ctx, &config.Instance{}, paths); err != nil {
			t.Fatalf("EnsureAccess with no disk: %v", err)
		}
	})

	t.Run("repairs a stripped mode back to owner-only", func(t *testing.T) {
		paths := newDiskTestPaths(t)
		writeFakeImage(t, instanceDiskPath(paths), 512)
		if err := os.Chmod(instanceDiskPath(paths), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := m.EnsureAccess(ctx, &config.Instance{}, paths); err != nil {
			t.Fatalf("EnsureAccess: %v", err)
		}
		info, _ := os.Stat(instanceDiskPath(paths))
		if info.Mode().Perm() != diskPerm {
			t.Errorf("disk mode = %o, want %o", info.Mode().Perm(), diskPerm)
		}
	})
}

func TestHumanizeBytes(t *testing.T) {
	const gib = int64(1024 * 1024 * 1024)
	tests := []struct {
		name string
		in   int64
		want string
	}{
		{name: "zero rounds up to at least 1G", in: 0, want: "1G"},
		{name: "one byte rounds up to 1G", in: 1, want: "1G"},
		{name: "exactly 1 GiB", in: gib, want: "1G"},
		{name: "1 GiB + 1 byte rounds up to 2G", in: gib + 1, want: "2G"},
		{name: "exactly 4 GiB", in: 4 * gib, want: "4G"},
		{name: "just under 4 GiB rounds up to 4G", in: 4*gib - 1, want: "4G"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := humanizeBytes(tt.in); got != tt.want {
				t.Errorf("humanizeBytes(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestImport_SnapshotRejected verifies snapshot imports are rejected up front
// with an ErrHint, before any qemu-img invocation.
func TestImport_SnapshotRejected(t *testing.T) {
	m := &DiskManager{}
	// src/paths are never touched on the snapshot==true path, so empty values
	// exercise the early return without shelling out.
	err := m.Import(context.Background(), "", &config.Instance{}, &config.Paths{}, true)
	if err == nil {
		t.Fatal("expected an error for snapshot import, got nil")
	}
	var hint *errhint.ErrHint
	if !errors.As(err, &hint) {
		t.Fatalf("expected *errhint.ErrHint, got %T: %v", err, err)
	}
	if hint.Hint == "" {
		t.Error("expected a non-empty remediation hint")
	}
}

// TestExport_SnapshotRejected verifies snapshot exports are rejected up front
// with an ErrHint, before any qemu-img invocation.
func TestExport_SnapshotRejected(t *testing.T) {
	m := &DiskManager{}
	err := m.Export(context.Background(), "", &config.Paths{}, true)
	if err == nil {
		t.Fatal("expected an error for snapshot export, got nil")
	}
	var hint *errhint.ErrHint
	if !errors.As(err, &hint) {
		t.Fatalf("expected *errhint.ErrHint, got %T: %v", err, err)
	}
	if hint.Hint == "" {
		t.Error("expected a non-empty remediation hint")
	}
}
