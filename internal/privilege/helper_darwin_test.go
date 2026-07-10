//go:build darwin

package privilege

import (
	"testing"
)

func TestValidateInstanceName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid simple", input: "dev"},
		{name: "valid with hyphen", input: "my-instance"},
		{name: "valid with numbers", input: "test123"},
		{name: "valid uppercase", input: "MyVM"},
		{name: "empty", input: "", wantErr: true},
		{name: "semicolon injection", input: "dev;rm -rf /", wantErr: true},
		{name: "slash", input: "dev/test", wantErr: true},
		{name: "space", input: "dev test", wantErr: true},
		{name: "dot", input: "dev.test", wantErr: true},
		{name: "underscore", input: "dev_test", wantErr: true},
		{name: "newline", input: "dev\ntest", wantErr: true},
		{name: "too long", input: "a-very-long-instance-name-that-exceeds-the-sixty-three-character-maximum-limit", wantErr: true},
		{name: "exactly 63 chars", input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInstanceName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateInstanceName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseOctalMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint32
		wantErr bool
	}{
		{name: "standard file", input: "644", want: 0o644},
		{name: "standard dir", input: "755", want: 0o755},
		{name: "restrictive", input: "600", want: 0o600},
		{name: "four digit", input: "0755", want: 0o755},
		{name: "all zeros", input: "000", want: 0},
		{name: "all sevens", input: "777", want: 0o777},
		{name: "invalid octal digit", input: "689", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "text", input: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := parseOctalMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOctalMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if err == nil && uint32(mode) != tt.want {
				t.Errorf("parseOctalMode(%q) = %o, want %o", tt.input, mode, tt.want)
			}
		})
	}
}

func TestResolveCommands_Darwin(t *testing.T) {
	// Reset state for clean test
	resolvedCommands.mu.Lock()
	resolvedCommands.resolved = false
	resolvedCommands.paths = nil
	resolvedCommands.mu.Unlock()

	// ResolveCommands should succeed if pfctl and qemu-img are in PATH.
	// pfctl is always available on macOS; qemu-img may not be.
	// We test the resolution framework rather than specific commands.
	err := ResolveCommands()
	if err != nil {
		t.Skipf("skipping: required commands not found: %v", err)
	}

	pfctlPath := cmdPath("pfctl")
	if pfctlPath == "pfctl" {
		t.Error("pfctl should be resolved to absolute path")
	}
}
