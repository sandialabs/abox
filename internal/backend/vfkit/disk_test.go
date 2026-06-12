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

func TestParseDiskSize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{"1G", "1G", 1024 * 1024 * 1024, false},
		{"20G", "20G", 20 * 1024 * 1024 * 1024, false},
		{"100M", "100M", 100 * 1024 * 1024, false},
		{"512K", "512K", 512 * 1024, false},
		{"1T", "1T", 1024 * 1024 * 1024 * 1024, false},
		{"lowercase_g", "20g", 20 * 1024 * 1024 * 1024, false},
		{"empty", "", 0, true},
		{"no_suffix", "20", 0, true},
		{"single_char", "G", 0, true},
		{"bad_number", "abcG", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDiskSize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDiskSize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDiskSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseBackingFilename(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    string
		wantErr bool
	}{
		{
			name: "no backing file",
			json: `{"virtual-size": 1073741824, "filename": "disk.qcow2", "format": "qcow2"}`,
			want: "",
		},
		{
			name: "with backing file",
			json: `{"virtual-size": 1073741824, "filename": "disk.qcow2", "format": "qcow2", "backing-filename": "/var/lib/abox/base.qcow2"}`,
			want: "/var/lib/abox/base.qcow2",
		},
		{
			name:    "invalid json",
			json:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBackingFilename([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseBackingFilename() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseBackingFilename() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHumanizeBytes(t *testing.T) {
	const gib = 1024 * 1024 * 1024
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"exact 1G", gib, "1G"},
		{"3.5G rounds up to 4G", gib*3 + gib/2, "4G"},
		{"just over 1G rounds up to 2G", gib + 1, "2G"},
		{"zero rounds up to 1G", 0, "1G"},
		{"sub-gigabyte rounds up to 1G", 1024, "1G"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := humanizeBytes(tt.bytes); got != tt.want {
				t.Errorf("humanizeBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestSelfContainedExport(t *testing.T) {
	var m DiskManager
	if !m.SelfContainedExport() {
		t.Error("vfkit DiskManager.SelfContainedExport() = false, want true")
	}
}

// TestCreateRejectsShrink verifies F15: Create must refuse a --disk smaller than
// the cloned base image rather than truncating away the filesystem tail.
func TestCreateRejectsShrink(t *testing.T) {
	dir := t.TempDir()

	// Stand in for the raw base image: a 4 MiB file (the real ubuntu base is
	// larger than the 1G validation floor, which is the crux of the bug).
	baseImages := filepath.Join(dir, "base")
	if err := os.MkdirAll(baseImages, 0o755); err != nil {
		t.Fatal(err)
	}
	baseImage := filepath.Join(baseImages, "ubuntu.raw")
	const baseSize = 4 * 1024 * 1024
	if err := os.WriteFile(baseImage, make([]byte, baseSize), 0o644); err != nil {
		t.Fatal(err)
	}

	diskDir := filepath.Join(dir, "disk")
	paths := &config.Paths{
		BaseImages: baseImages,
		DiskDir:    diskDir,
		Disk:       filepath.Join(diskDir, "disk.raw"),
	}
	inst := &config.Instance{Base: "ubuntu", Disk: "1M"} // 1 MiB < 4 MiB base

	var m DiskManager
	err := m.Create(context.Background(), nil, inst, paths)
	if err == nil {
		t.Fatal("Create() with a disk smaller than the base image succeeded, want error")
	}
	var hintErr *errhint.ErrHint
	if !errors.As(err, &hintErr) {
		t.Fatalf("Create() error = %v, want *errhint.ErrHint with size guidance", err)
	}
	// The clone must not have been truncated below the base size.
	if info, statErr := os.Stat(paths.Disk); statErr == nil && info.Size() < int64(baseSize) {
		t.Errorf("disk was truncated to %d bytes, below base size %d", info.Size(), baseSize)
	}
}

// TestCreateGrowsDisk verifies the happy path still grows the disk when the
// requested size exceeds the base image.
func TestCreateGrowsDisk(t *testing.T) {
	dir := t.TempDir()
	baseImages := filepath.Join(dir, "base")
	if err := os.MkdirAll(baseImages, 0o755); err != nil {
		t.Fatal(err)
	}
	baseImage := filepath.Join(baseImages, "ubuntu.raw")
	const baseSize = 4 * 1024 * 1024
	if err := os.WriteFile(baseImage, make([]byte, baseSize), 0o644); err != nil {
		t.Fatal(err)
	}

	diskDir := filepath.Join(dir, "disk")
	paths := &config.Paths{
		BaseImages: baseImages,
		DiskDir:    diskDir,
		Disk:       filepath.Join(diskDir, "disk.raw"),
	}
	inst := &config.Instance{Base: "ubuntu", Disk: "8M"} // grow to 8 MiB

	var m DiskManager
	if err := m.Create(context.Background(), nil, inst, paths); err != nil {
		t.Fatalf("Create() = %v, want nil", err)
	}
	info, err := os.Stat(paths.Disk)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(8 * 1024 * 1024); info.Size() != want {
		t.Errorf("disk size = %d, want %d", info.Size(), want)
	}
}
