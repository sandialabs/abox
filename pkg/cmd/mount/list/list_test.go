package list

import (
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdList_ParsesInstance(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdList(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"dev"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if gotOpts.Name != "dev" {
		t.Errorf("Name = %q, want %q", gotOpts.Name, "dev")
	}
}

func TestNewCmdList_HasLsAlias(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdList(f, nil)
	found := false
	for _, a := range cmd.Aliases {
		if a == "ls" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'ls' alias, got %v", cmd.Aliases)
	}
}

func TestNewCmdList_RequiresInstance(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdList(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no instance provided")
	}
}
