package provision

import (
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdProvision_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdProvision(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--script", "setup.sh", "--overlay", "/tmp/overlay", "myvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if len(gotOpts.Scripts) != 1 || gotOpts.Scripts[0] != "setup.sh" {
		t.Errorf("Scripts = %v, want [setup.sh]", gotOpts.Scripts)
	}
	if gotOpts.Overlay != "/tmp/overlay" {
		t.Errorf("Overlay = %q, want %q", gotOpts.Overlay, "/tmp/overlay")
	}
	if gotOpts.Name != "myvm" {
		t.Errorf("Name = %q, want %q", gotOpts.Name, "myvm")
	}
}

func TestNewCmdProvision_RequiresName(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdProvision(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no name provided")
	}
}
