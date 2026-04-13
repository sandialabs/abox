package remove

import (
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

type mockPrompter struct {
	confirmResult bool
}

func (m *mockPrompter) Confirm(msg string) bool                               { return m.confirmResult }
func (m *mockPrompter) ConfirmWithDefault(msg string, defaultYes bool) bool   { return m.confirmResult }
func (m *mockPrompter) Select(promptMsg string, options []cmdutil.Option) int { return 0 }
func (m *mockPrompter) SelectWithGroups(promptMsg string, groups map[string][]cmdutil.Option, groupOrder []string) int {
	return 0
}
func (m *mockPrompter) Input(prompt string, defaultValue string) string { return defaultValue }
func (m *mockPrompter) MultiSelect(prompt string, options []cmdutil.Option) []int {
	return nil
}

func TestNewCmdRemove_ForceFlag(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
		Prompter:    &mockPrompter{confirmResult: true},
	}

	var gotOpts *Options
	cmd := NewCmdRemove(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--force", "myvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.Force {
		t.Error("expected Force to be true")
	}
	if len(gotOpts.Names) != 1 || gotOpts.Names[0] != "myvm" {
		t.Errorf("Names = %v, want [myvm]", gotOpts.Names)
	}
}

func TestNewCmdRemove_MultipleInstances(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{
		IO:          ios,
		ColorScheme: cmdutil.NewColorScheme(false),
		Prompter:    &mockPrompter{confirmResult: true},
	}

	var gotOpts *Options
	cmd := NewCmdRemove(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--force", "a", "b", "c"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	want := []string{"a", "b", "c"}
	if len(gotOpts.Names) != len(want) {
		t.Fatalf("Names length = %d, want %d", len(gotOpts.Names), len(want))
	}
	for i, name := range want {
		if gotOpts.Names[i] != name {
			t.Errorf("Names[%d] = %q, want %q", i, gotOpts.Names[i], name)
		}
	}
}
