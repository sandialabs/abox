package add

import (
	"testing"

	"github.com/sandialabs/abox/internal/iostreams"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

func TestNewCmdAdd_FlagParsing(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	var gotOpts *Options
	cmd := NewCmdAdd(f, func(o *Options) error {
		gotOpts = o
		return nil
	})
	cmd.SetArgs([]string{"--reverse", "dev", "8080:80"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOpts == nil {
		t.Fatal("runF was not called")
	}
	if !gotOpts.Reverse {
		t.Error("expected Reverse to be true")
	}
	if gotOpts.Name != "dev" {
		t.Errorf("Name = %q, want %q", gotOpts.Name, "dev")
	}
	if gotOpts.Mapping != "8080:80" {
		t.Errorf("Mapping = %q, want %q", gotOpts.Mapping, "8080:80")
	}
}

func TestNewCmdAdd_RequiresArgs(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &factory.Factory{IO: ios, ColorScheme: cmdutil.NewColorScheme(false)}

	cmd := NewCmdAdd(f, func(o *Options) error {
		t.Fatal("runF should not be called")
		return nil
	})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no args provided")
	}
}

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		wantHost  int
		wantGuest int
		wantErr   bool
	}{
		{"valid", "8080:80", 8080, 80, false},
		{"same ports", "3000:3000", 3000, 3000, false},
		{"max port", "65535:65535", 65535, 65535, false},
		{"port 1", "1:1", 1, 1, false},
		{"invalid format", "8080", 0, 0, true},
		{"too many parts", "8080:80:90", 0, 0, true},
		{"zero host port", "0:80", 0, 0, true},
		{"zero guest port", "80:0", 0, 0, true},
		{"host port too high", "65536:80", 0, 0, true},
		{"non-numeric", "abc:80", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, guest, err := parsePortSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePortSpec(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if host != tt.wantHost {
					t.Errorf("host = %d, want %d", host, tt.wantHost)
				}
				if guest != tt.wantGuest {
					t.Errorf("guest = %d, want %d", guest, tt.wantGuest)
				}
			}
		})
	}
}
