package status

import (
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdStatus_JSONFlag(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdStatus(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--json", "myvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.Exporter.Enabled() {
		t.Error("expected Exporter.Enabled() to be true when --json is passed")
	}
	if len(gotOpts.Names) != 1 || gotOpts.Names[0] != "myvm" {
		t.Errorf("Names = %v, want [myvm]", gotOpts.Names)
	}
}

func TestNewCmdStatus_MultipleInstances(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdStatus(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"a", "b", "c"})

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
