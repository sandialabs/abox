package dump

import (
	"bytes"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	_ "github.com/sandialabs/abox/internal/backend/libvirt" // register libvirt override defaults
	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestDump_KnownKey(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	var stdout bytes.Buffer
	ios.Out = &stdout
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdDump(f)
	cmd.SetArgs([]string{"libvirt.template"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected non-empty output for libvirt.template")
	}
}

func TestDump_UnknownKey(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdDump(f)
	cmd.SetArgs([]string{"nonexistent.key"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() should return error for unknown key")
	}
}

func TestDump_OutputMatchesRegistry(t *testing.T) {
	for key, entry := range backend.OverrideDefaults() {
		t.Run(key, func(t *testing.T) {
			ios, _, _, _ := iostreams.Test()
			var stdout bytes.Buffer
			ios.Out = &stdout
			f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

			cmd := NewCmdDump(f)
			cmd.SetArgs([]string{key})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			want := entry.Fn()
			if got := stdout.String(); got != want {
				t.Errorf("output mismatch for %s:\ngot  %d bytes\nwant %d bytes", key, len(got), len(want))
			}
		})
	}
}

func TestAvailableKeys(t *testing.T) {
	keys := availableKeys()
	if len(keys) == 0 {
		t.Fatal("availableKeys() returned empty list")
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] < keys[i-1] {
			t.Errorf("keys not sorted: %q before %q", keys[i-1], keys[i])
		}
	}
}
