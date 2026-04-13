package privilege

import (
	"fmt"
	"os"
	"testing"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid path", "/var/lib/libvirt/images/abox/instance/disk.qcow2", false},
		{"valid base path", "/var/lib/libvirt/images/abox", false},
		{"path traversal with ..", "/var/lib/libvirt/images/abox/../../etc/passwd", true},
		{"path traversal at start", "../var/lib/libvirt/images/abox/file", true},
		{"path traversal mid-path", "/var/lib/libvirt/images/abox/../../../etc/shadow", true},
		{"outside allowed paths", "/tmp/malicious.qcow2", true},
		{"outside allowed paths /etc", "/etc/passwd", true},
		{"root path", "/", true},
		{"empty path", "", true},
		{"home directory", "/home/user/file", true},
		{"close but not allowed", "/var/lib/libvirt/images/aboxextra/file", true},
		{"prefix without slash", "/var/lib/libvirt/images/abox-other/file", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRemoveAllPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid deep path", "/var/lib/libvirt/images/abox/instance/subdir", false},
		{"exact base - too shallow", "/var/lib/libvirt/images/abox", true},
		{"one level deep - 6 components ok", "/var/lib/libvirt/images/abox/instance", false},
		{"path traversal", "/var/lib/libvirt/images/abox/../../etc", true},
		{"outside allowed", "/tmp/something/deep/path/here/file", true},
		{"6 components valid", "/var/lib/libvirt/images/abox/myvm", false},
		{"7 components valid", "/var/lib/libvirt/images/abox/myvm/disk", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRemoveAllPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRemoveAllPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		// Valid: alphanumeric, path separators, common file path chars
		{"clean args", []string{"hello", "world"}, false},
		{"normal path", []string{"/var/lib/libvirt/images/abox/file.qcow2"}, false},
		{"path with hyphen", []string{"/var/lib/libvirt/images/abox/my-vm/disk.qcow2"}, false},
		{"path with underscore", []string{"/var/lib/libvirt/images/abox/my_vm/disk.qcow2"}, false},
		{"path with plus", []string{"/var/lib/libvirt/images/abox/g++/file"}, false},
		{"path with colon", []string{"key:value"}, false},
		{"path with equals", []string{"key=value"}, false},
		{"path with at", []string{"user@host"}, false},
		{"empty args", []string{}, false},
		{"empty string", []string{""}, false},

		// Invalid: shell metacharacters
		{"semicolon", []string{"cmd;evil"}, true},
		{"pipe", []string{"cmd|evil"}, true},
		{"ampersand", []string{"cmd&evil"}, true},
		{"dollar", []string{"$HOME"}, true},
		{"backtick", []string{"`whoami`"}, true},
		{"backslash", []string{`cmd\n`}, true},
		{"angle brackets", []string{"<input"}, true},
		{"parentheses", []string{"$(cmd)"}, true},
		{"curly braces", []string{"{a,b}"}, true},

		// Invalid: characters missed by denylist but caught by allowlist
		{"null byte", []string{"file\x00evil"}, true},
		{"newline", []string{"file\nevil"}, true},
		{"carriage return", []string{"file\revil"}, true},
		{"space", []string{"file evil"}, true},
		{"tab", []string{"file\tevil"}, true},
		{"glob star", []string{"file*"}, true},
		{"glob question", []string{"file?"}, true},
		{"glob brackets", []string{"file[0]"}, true},
		{"unicode", []string{"file\u00e9"}, true},
		{"tilde", []string{"~/file"}, true},
		{"hash", []string{"file#1"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArgs(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestValidateBridgeName(t *testing.T) {
	tests := []struct {
		name    string
		bridge  string
		wantErr bool
	}{
		{"valid abox prefix", "abox-myvm", false},
		{"valid ab prefix", "ab-1a2b3c", false},
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

func TestValidateChmodMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"valid 644", "644", false},
		{"valid 755", "755", false},
		{"valid 0644", "0644", false},
		{"valid 0777", "0777", false},
		{"valid 000", "000", false},
		{"valid 777", "777", false},
		{"invalid digit 8", "844", true},
		{"invalid digit 9", "649", true},
		{"too short", "64", true},
		{"too long", "06444", true},
		{"empty", "", true},
		{"symbolic mode", "u+x", true},
		{"letters", "abc", true},
		{"special chars", "7;7", true},
		{"negative", "-644", true},
		{"with spaces", " 644", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChmodMode(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateChmodMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDiskSize(t *testing.T) {
	tests := []struct {
		name    string
		size    string
		wantErr bool
	}{
		{"valid 1G", "1G", false},
		{"valid 20G", "20G", false},
		{"valid 100G", "100G", false},
		{"valid 10240G", "10240G", false},
		{"valid 1T", "1T", false},
		{"valid 10T", "10T", false},
		{"over max G", "10241G", true},
		{"over max T", "11T", true},
		{"zero G", "0G", true},
		{"negative G", "-1G", true},
		{"K suffix rejected", "1024K", true},
		{"M suffix rejected", "512M", true},
		{"no suffix", "20", true},
		{"too short", "G", true},
		{"empty", "", true},
		{"letters in number", "abcG", true},
		{"float number", "1.5G", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiskSize(tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDiskSize(%q) error = %v, wantErr %v", tt.size, err, tt.wantErr)
			}
		})
	}
}

func TestValidateBackingFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid abox path", "/var/lib/libvirt/images/abox/base/ubuntu.qcow2", false},
		{"images path outside abox subdir", "/var/lib/libvirt/images/ubuntu-24.04.qcow2", true},
		{"not qcow2", "/var/lib/libvirt/images/abox/base/ubuntu.raw", true},
		{"path traversal", "/var/lib/libvirt/images/abox/../../../etc/passwd.qcow2", true},
		{"outside allowed", "/tmp/malicious.qcow2", true},
		{"home directory", "/home/user/disk.qcow2", true},
		{"shell metachar", "/var/lib/libvirt/images/abox/test;evil.qcow2", true},
		{"empty", "", true},
		{"no extension", "/var/lib/libvirt/images/abox/disk", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackingFile(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBackingFile(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCopySource(t *testing.T) {
	uid := os.Getuid()
	server := &PrivilegeServer{allowedUID: uid}

	// Get current user's home directory for constructing valid test paths
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		// Valid paths
		{"valid base qcow2", homeDir + "/.local/share/abox/base/ubuntu.qcow2", false},
		{"valid instance qcow2", homeDir + "/.local/share/abox/instances/myvm/disk.qcow2", false},
		{"valid base iso", homeDir + "/.local/share/abox/base/cloud-init.iso", false},
		{"valid instance iso", homeDir + "/.local/share/abox/instances/myvm/cloud-init.iso", false},
		{"valid run user qcow2", fmt.Sprintf("/run/user/%d/abox-tmp.qcow2", uid), false},
		{"valid run user iso", fmt.Sprintf("/run/user/%d/cloud-init.iso", uid), false},

		// Invalid paths
		{"tmp rejected", "/tmp/malicious.qcow2", true},
		{"wrong extension", homeDir + "/.local/share/abox/base/file.txt", true},
		{"path traversal", homeDir + "/.local/share/abox/base/../../etc/passwd.qcow2", true},
		{"wrong home subdir", homeDir + "/.config/abox/base/file.qcow2", true},
		{"outside abox dir", homeDir + "/.local/share/other/file.qcow2", true},
		{"shell metachar", homeDir + "/.local/share/abox/base/test;evil.qcow2", true},
		{"wrong user run dir", "/run/user/0/file.qcow2", true},
		{"empty", "", true},
		{"root path", "/file.qcow2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.validateCopySource(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCopySource(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateNonExistentPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		// Paths under the allowed base that don't exist yet should pass
		// (the ancestor /var/lib/libvirt/images/abox or at least /var exists)
		{"non-existent under allowed base", "/var/lib/libvirt/images/abox/newinstance/disk.qcow2", false},
		{"deeply nested non-existent", "/var/lib/libvirt/images/abox/a/b/c/d.qcow2", false},

		// Paths outside allowed bases should fail even if ancestors exist
		{"outside allowed - tmp", "/tmp/nonexistent/file.qcow2", true},
		{"outside allowed - etc", "/etc/nonexistent/file.qcow2", true},
		{"outside allowed - home", "/home/nonexistent-user/.local/share/file.qcow2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNonExistentPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateNonExistentPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePathNoSymlinks_NonExistent(t *testing.T) {
	// Test ValidatePathNoSymlinks with non-existent paths under allowed base
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"new file under allowed base", "/var/lib/libvirt/images/abox/future-vm/disk.qcow2", false},
		{"outside allowed base", "/tmp/future-vm/disk.qcow2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePathNoSymlinks(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePathNoSymlinks(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSocketPath(t *testing.T) {
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

func TestValidateCopySourceWrongUID(t *testing.T) {
	// Use a UID that doesn't match the current user
	server := &PrivilegeServer{allowedUID: 99999}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	// Path would be valid with the right UID but should fail with wrong UID
	err = server.validateCopySource(homeDir + "/.local/share/abox/base/ubuntu.qcow2")
	if err == nil {
		t.Error("validateCopySource should reject paths when home dir UID doesn't match allowedUID")
	}
}
