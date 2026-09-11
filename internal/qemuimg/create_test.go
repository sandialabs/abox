package qemuimg

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// makeQcow2 creates a small standalone qcow2 at path via the real qemu-img.
func makeQcow2(t *testing.T, ctx context.Context, path, size string) {
	t.Helper()
	if out, err := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2", path, size).CombinedOutput(); err != nil {
		t.Fatalf("create qcow2 %s: %s: %v", path, out, err)
	}
}

func TestFormatDetectsByContent(t *testing.T) {
	requireQemuImg(t)
	ctx := context.Background()
	dir := t.TempDir()

	// A qcow2 given a misleading ".img" extension must still be reported as qcow2
	// (detection is by content, which security decisions rely on).
	p := filepath.Join(dir, "disk.img")
	makeQcow2(t, ctx, p, "8M")

	got, err := Format(ctx, p)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if got != "qcow2" {
		t.Fatalf("Format = %q, want qcow2", got)
	}
}

func TestCreateBacksAndBackingFileReports(t *testing.T) {
	requireQemuImg(t)
	ctx := context.Background()
	dir := t.TempDir()

	base := filepath.Join(dir, "base.qcow2")
	makeQcow2(t, ctx, base, "16M")

	// A standalone image has no backing file.
	if bf, err := BackingFile(ctx, base); err != nil {
		t.Fatalf("BackingFile(base): %v", err)
	} else if bf != "" {
		t.Fatalf("standalone BackingFile = %q, want empty", bf)
	}

	disk := filepath.Join(dir, "disk.qcow2")
	if err := Create(ctx, base, disk, "16M"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := imgFormat(t, disk); got != "qcow2" {
		t.Fatalf("created disk format = %q, want qcow2", got)
	}
	bf, err := BackingFile(ctx, disk)
	if err != nil {
		t.Fatalf("BackingFile(disk): %v", err)
	}
	if bf != base {
		t.Fatalf("BackingFile = %q, want %q", bf, base)
	}
}

func TestRebaseRepointsBackingFile(t *testing.T) {
	requireQemuImg(t)
	ctx := context.Background()
	dir := t.TempDir()

	base1 := filepath.Join(dir, "base1.qcow2")
	base2 := filepath.Join(dir, "base2.qcow2")
	makeQcow2(t, ctx, base1, "16M")
	makeQcow2(t, ctx, base2, "16M")

	disk := filepath.Join(dir, "disk.qcow2")
	if err := Create(ctx, base1, disk, "16M"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Unsafe rebase onto a byte-identical relocated base.
	if err := Rebase(ctx, disk, base2); err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	bf, err := BackingFile(ctx, disk)
	if err != nil {
		t.Fatalf("BackingFile: %v", err)
	}
	if bf != base2 {
		t.Fatalf("after Rebase, BackingFile = %q, want %q", bf, base2)
	}
}

func TestConvertProducesSelfContained(t *testing.T) {
	requireQemuImg(t)
	ctx := context.Background()
	dir := t.TempDir()

	base := filepath.Join(dir, "base.qcow2")
	makeQcow2(t, ctx, base, "16M")
	disk := filepath.Join(dir, "disk.qcow2")
	if err := Create(ctx, base, disk, "16M"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	flat := filepath.Join(dir, "flat.qcow2")
	if err := Convert(ctx, disk, flat, false); err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if got := imgFormat(t, flat); got != "qcow2" {
		t.Fatalf("converted format = %q, want qcow2", got)
	}
	// The merged output must carry no backing file (fully self-contained).
	if bf, err := BackingFile(ctx, flat); err != nil {
		t.Fatalf("BackingFile(flat): %v", err)
	} else if bf != "" {
		t.Fatalf("converted BackingFile = %q, want empty (self-contained)", bf)
	}
}
