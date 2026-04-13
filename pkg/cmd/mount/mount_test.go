package mount

import (
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdMount_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdMount(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--read-only", "--allow-other", "dev", "/mnt/dev"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.ReadOnly {
		t.Error("expected ReadOnly to be true")
	}
	if !gotOpts.AllowOther {
		t.Error("expected AllowOther to be true")
	}
	if gotOpts.Name != "dev" {
		t.Errorf("Name = %q, want %q", gotOpts.Name, "dev")
	}
	if gotOpts.MountPoint != "/mnt/dev" {
		t.Errorf("MountPoint = %q, want %q", gotOpts.MountPoint, "/mnt/dev")
	}
}

func TestNewCmdMount_RequiresArgs(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdMount(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no args provided")
	}
}
