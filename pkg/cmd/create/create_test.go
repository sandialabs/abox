package create

import (
	"testing"

	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// createPrivilegeProvider is a mock backend that implements
// backend.CreatePrivilegeProvider, reporting the configured value.
type createPrivilegeProvider struct {
	*mock.Backend
	requires bool
}

func (b *createPrivilegeProvider) CreateRequiresPrivilege() bool {
	return b.requires
}

func TestCreateRequiresPrivilege_DefaultsToTrue(t *testing.T) {
	// A backend that does not implement CreatePrivilegeProvider must default
	// to requiring privileges (Linux/libvirt behavior).
	if !createRequiresPrivilege(&mock.Backend{}) {
		t.Error("expected createRequiresPrivilege to default to true for a backend without the interface")
	}
}

func TestCreateRequiresPrivilege_HonorsProvider(t *testing.T) {
	if createRequiresPrivilege(&createPrivilegeProvider{Backend: &mock.Backend{}, requires: false}) {
		t.Error("expected createRequiresPrivilege to be false when the backend reports no privilege need")
	}
	if !createRequiresPrivilege(&createPrivilegeProvider{Backend: &mock.Backend{}, requires: true}) {
		t.Error("expected createRequiresPrivilege to be true when the backend reports a privilege need")
	}
}

func TestNewCmdCreate_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdCreate(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--cpus", "4", "--memory", "8192", "--base", "ubuntu-24.04", "--dry-run", "myvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if gotOpts.CPUs != 4 {
		t.Errorf("CPUs = %d, want 4", gotOpts.CPUs)
	}
	if gotOpts.Memory != 8192 {
		t.Errorf("Memory = %d, want 8192", gotOpts.Memory)
	}
	if gotOpts.Base != "ubuntu-24.04" {
		t.Errorf("Base = %q, want %q", gotOpts.Base, "ubuntu-24.04")
	}
	if !gotOpts.DryRun {
		t.Error("expected DryRun to be true")
	}
	if gotOpts.Name != "myvm" {
		t.Errorf("Name = %q, want %q", gotOpts.Name, "myvm")
	}
}

func TestNewCmdCreate_RequiresName(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdCreate(f, func(o *Options) error {
		t.Fatal("runF should not be called when name is missing")
		return nil
	})
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no name and no --from-file is provided")
	}
}
