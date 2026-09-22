package privilege

import (
	"runtime"
	"testing"
)

func TestValidateBridgeName(t *testing.T) {
	tests := []struct {
		name    string
		bridge  string
		wantErr bool
	}{
		{"valid abox prefix", "abox-myvm", false},
		{"valid ab prefix", "ab-1a2b3c", false},
		{"valid vmnet", "vmnet2", false},
		{"valid abox-foo", "abox-foo", false},
		{"vmnet no digits", "vmnet", true},
		{"eth0", "eth0", true},
		{"vmnet with injection", "vmnet2;evil", true},
		{"no prefix", "br-myvm", true},
		{"empty", "", true},
		{"semicolon", "abox-vm;evil", true},
		{"pipe", "abox-vm|evil", true},
		{"ampersand", "abox-vm&evil", true},
		{"backtick", "abox-vm`evil`", true},
		{"dollar", "abox-$vm", true},
		{"space", "abox- vm", true},
		{"dot", "abox-vm.1", true},
		{"underscore", "abox-vm_1", true},
		{"valid with numbers", "abox-vm123", false},
		{"valid with hyphens", "ab-abc-def", false},
		{"exactly 15 chars", "abox-1234567890", false},
		{"16 chars too long", "abox-12345678901", true},
		{"ab prefix at limit", "ab-123456789012", false},
		{"ab prefix over limit", "ab-1234567890123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBridgeName(tt.bridge)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBridgeName(%q) error = %v, wantErr %v", tt.bridge, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSocketPath(t *testing.T) {
	// ValidateSocketPath guards the Unix-domain helper socket path. Its
	// cleanliness check uses filepath.Clean, which rewrites '/'→'\' on Windows
	// and rejects every POSIX-style path in this table. The helper is unsupported
	// on Windows anyway (helper_other.go), so this is a unix-only concern.
	if runtime.GOOS == "windows" {
		t.Skip("ValidateSocketPath validates POSIX helper socket paths; helper is unsupported on Windows")
	}
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid absolute path", "/run/user/1000/abox.sock", false},
		{"valid clean path", "/tmp/test.sock", false},
		{"empty", "", true},
		{"relative path", "relative/path.sock", true},
		{"path with ..", "/run/user/../tmp/sock", true},
		{"trailing slash", "/run/user/1000/", true},
		{"double slash", "/run//user/1000/sock", true},
		{"dot segment", "/run/./user/sock", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSocketPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSocketPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}
