package prune

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func newTestFactory() *factory.Factory {
	ios, _, _, _ := iostreams.Test()
	return &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
	}
}

func TestNewCmdPrune_RequiresForceOrDryRun(t *testing.T) {
	f := newTestFactory()

	cmd := NewCmdPrune(f, func(o *Options) error {
		t.Fatal("runF should not be called without --force or --dry-run")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when neither --force nor --dry-run provided")
	}
}

func TestNewCmdPrune_ForceFlag(t *testing.T) {
	f := newTestFactory()

	var gotOpts *Options
	cmd := NewCmdPrune(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"-f"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.Force {
		t.Error("expected Force to be true")
	}
	if gotOpts.DryRun {
		t.Error("expected DryRun to be false")
	}
}

func TestNewCmdPrune_DryRunFlag(t *testing.T) {
	f := newTestFactory()

	var gotOpts *Options
	cmd := NewCmdPrune(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"-n"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.DryRun {
		t.Error("expected DryRun to be true")
	}
	if gotOpts.Force {
		t.Error("expected Force to be false")
	}
}

func TestNewCmdPrune_BothFlags(t *testing.T) {
	f := newTestFactory()

	var gotOpts *Options
	cmd := NewCmdPrune(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"-f", "-n"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotOpts.Force || !gotOpts.DryRun {
		t.Error("expected both Force and DryRun to be true")
	}
}

func TestNewCmdPrune_RejectsArgs(t *testing.T) {
	f := newTestFactory()

	cmd := NewCmdPrune(f, func(o *Options) error {
		t.Fatal("runF should not be called with positional args")
		return nil
	})
	cmd.SetArgs([]string{"-f", "extra"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error with positional args")
	}
}

func TestFindUnusedImages(t *testing.T) {
	dir := t.TempDir()

	// Create some qcow2 files
	for _, name := range []string{"ubuntu-24.04.qcow2", "debian-12.qcow2", "fedora-40.qcow2", "readme.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	referenced := map[string]bool{
		"ubuntu-24.04": true,
	}

	unused, err := findUnusedImages(dir, referenced)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]bool{"debian-12": true, "fedora-40": true}
	if len(unused) != len(want) {
		t.Fatalf("got %d unused images, want %d", len(unused), len(want))
	}
	for _, name := range unused {
		if !want[name] {
			t.Errorf("unexpected unused image: %s", name)
		}
	}
}

func TestFindUnusedImages_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	unused, err := findUnusedImages(dir, map[string]bool{"foo": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unused) != 0 {
		t.Fatalf("expected no unused images, got %d", len(unused))
	}
}

func TestFindUnusedImages_MissingDir(t *testing.T) {
	unused, err := findUnusedImages("/nonexistent/path", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unused != nil {
		t.Fatalf("expected nil, got %v", unused)
	}
}

func TestFindUnusedImages_AllReferenced(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "ubuntu-24.04.qcow2"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	unused, err := findUnusedImages(dir, map[string]bool{"ubuntu-24.04": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unused) != 0 {
		t.Fatalf("expected no unused images, got %d", len(unused))
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{500, "500 bytes"},
		{2 * 1024 * 1024, "2.0 MB"},
		{3 * 1024 * 1024 * 1024, "3.0 GB"},
	}
	for _, tt := range tests {
		got := formatSize(tt.bytes)
		if got != tt.want {
			t.Errorf("formatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}
