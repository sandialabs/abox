package config

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestGenerateBridgeName(t *testing.T) {
	tests := []struct {
		name     string
		instance string
		want     string
		wantLen  int // expected length, 0 means any
	}{
		{
			name:     "short name",
			instance: "dev",
			want:     "abox-dev",
		},
		{
			name:     "exactly 15 chars",
			instance: "myinstance",
			want:     "abox-myinstance", // 15 chars exactly
		},
		{
			name:     "one over limit needs hash",
			instance: "myinstance2",
			wantLen:  15, // hashed: ab-<12 hex chars>
		},
		{
			name:     "very long name needs hash",
			instance: "verylonginstancename",
			wantLen:  15,
		},
		{
			name:     "maximum allowed instance name",
			instance: "a12345678901234567890123456789012345678901234567890123456789012", // 63 chars
			wantLen:  15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateBridgeName(tt.instance)

			// Check exact value if specified
			if tt.want != "" && got != tt.want {
				t.Errorf("GenerateBridgeName(%q) = %q, want %q", tt.instance, got, tt.want)
			}

			// Check length constraint
			if len(got) > 15 {
				t.Errorf("GenerateBridgeName(%q) = %q (len=%d), exceeds 15 char limit",
					tt.instance, got, len(got))
			}

			// Check expected length if specified
			if tt.wantLen > 0 && len(got) != tt.wantLen {
				t.Errorf("GenerateBridgeName(%q) = %q (len=%d), want len=%d",
					tt.instance, got, len(got), tt.wantLen)
			}
		})
	}
}

func TestGenerateBridgeName_Deterministic(t *testing.T) {
	// Same input should always produce same output
	name := "verylonginstancename"
	first := GenerateBridgeName(name)
	second := GenerateBridgeName(name)

	if first != second {
		t.Errorf("GenerateBridgeName not deterministic: %q != %q", first, second)
	}
}

func TestGenerateBridgeName_UniqueHashes(t *testing.T) {
	// Different long names should produce different hashes
	name1 := "verylonginstance1"
	name2 := "verylonginstance2"

	bridge1 := GenerateBridgeName(name1)
	bridge2 := GenerateBridgeName(name2)

	if bridge1 == bridge2 {
		t.Errorf("Different names produced same bridge: %q and %q both -> %q",
			name1, name2, bridge1)
	}
}

func TestLoad_WithMock(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 1
name: test
cpus: 2
memory: 4096
disk: 20G
base: ubuntu-24.04
subnet: 10.10.10.0/24
gateway: 10.10.10.1
bridge: abox-test
dns:
  port: 5353
  upstream: 8.8.8.8:53
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	inst, paths, err := Load("test")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if inst.Name != "test" {
		t.Errorf("Load().Name = %q, want %q", inst.Name, "test")
	}
	if inst.CPUs != 2 {
		t.Errorf("Load().CPUs = %d, want %d", inst.CPUs, 2)
	}
	if inst.Memory != 4096 {
		t.Errorf("Load().Memory = %d, want %d", inst.Memory, 4096)
	}
	if paths.Instance != "/home/testuser/.local/share/abox/instances/test" {
		t.Errorf("Load().paths.Instance = %q, unexpected", paths.Instance)
	}
}

func TestLoad_NotFound(t *testing.T) {
	mock := NewMockFileSystem()
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("nonexistent")
	if err == nil {
		t.Error("Load() expected error for nonexistent instance")
	}
}

func TestSave_WithMock(t *testing.T) {
	mock := NewMockFileSystem()
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	inst := &Instance{
		Name:    "test",
		CPUs:    4,
		Memory:  8192,
		Base:    "ubuntu-24.04",
		Subnet:  "10.10.20.0/24",
		Gateway: "10.10.20.1",
		Bridge:  "abox-test",
		DNS: DNSConfig{
			Port:     5354,
			Upstream: "8.8.8.8:53",
		},
	}

	paths := &Paths{
		Config: "/home/testuser/.local/share/abox/instances/test/config.yaml",
	}

	err := Save(inst, paths)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify the file was written
	data, ok := mock.Files[paths.Config]
	if !ok {
		t.Fatal("Save() did not write to config path")
	}

	// Verify content contains expected values
	content := string(data)
	if !contains(content, "name: test") {
		t.Error("Save() config missing name")
	}
	if !contains(content, "cpus: 4") {
		t.Error("Save() config missing cpus")
	}
}

func TestSave_BackendConfigRoundTrip(t *testing.T) {
	mock := NewMockFileSystem()
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	inst := &Instance{
		Version: CurrentInstanceVersion,
		Name:    "test",
		CPUs:    2,
		Memory:  4096,
		Base:    "ubuntu-24.04",
		Subnet:  "10.10.10.0/24",
		Gateway: "10.10.10.1",
		Bridge:  "abox-test",
		BackendConfig: map[string]any{
			"custom_template": true,
		},
		SSHKey:     "/tmp/key",
		User:       "ubuntu",
		Disk:       "20G",
		MACAddress: "52:54:00:ab:cd:ef",
		IPAddress:  "10.10.10.2",
	}

	paths := &Paths{
		Config: "/home/testuser/.local/share/abox/instances/test/config.yaml",
	}

	if err := Save(inst, paths); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify BackendConfig round-trips through YAML
	data, ok := mock.Files[paths.Config]
	if !ok {
		t.Fatal("Save() did not write to config path")
	}

	content := string(data)
	if !contains(content, "custom_template: true") {
		t.Error("Save() config should contain custom_template flag")
	}

	// Unmarshal back and verify
	var loaded Instance
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal saved config: %v", err)
	}
	ct, ok := loaded.BackendConfig["custom_template"]
	if !ok || ct != true {
		t.Error("BackendConfig[\"custom_template\"] should be true after round-trip")
	}
}

func TestExists_WithMock(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte("version: 1\nname: test")
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	if !Exists("test") {
		t.Error("Exists(test) should be true")
	}
	if Exists("nonexistent") {
		t.Error("Exists(nonexistent) should be false")
	}
}

func TestList_WithMock(t *testing.T) {
	mock := NewMockFileSystem()
	mock.DirEntries["/home/testuser/.local/share/abox/instances"] = []os.DirEntry{
		&mockDirEntry{nameVal: "dev", isDirVal: true},
		&mockDirEntry{nameVal: "prod", isDirVal: true},
		&mockDirEntry{nameVal: "somefile", isDirVal: false},
	}
	// Only dev has a config file
	mock.Files["/home/testuser/.local/share/abox/instances/dev/config.yaml"] = []byte("version: 1\nname: dev")
	mock.Files["/home/testuser/.local/share/abox/instances/prod/config.yaml"] = []byte("version: 1\nname: prod")
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	names, err := List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(names) != 2 {
		t.Errorf("List() returned %d instances, want 2", len(names))
	}
}

func TestList_EmptyDir(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	names, err := List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(names) != 0 {
		t.Errorf("List() on empty/nonexistent dir should return nil or empty, got %v", names)
	}
}

func TestGetPaths_PathTraversal(t *testing.T) {
	mock := NewMockFileSystem()
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	tests := []struct {
		name      string
		instance  string
		wantError bool
	}{
		{"normal", "dev", false},
		{"with-hyphen", "my-instance", false},
		{"parent-dir", "../etc", true},
		{"double-parent", "../../passwd", true},
		// Note: absolute paths like "/etc/passwd" don't escape because they become
		// ".../instances//etc/passwd" which stays under instances. Instance name
		// validation (which happens elsewhere) would reject such names.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPaths(tt.instance)
			if tt.wantError {
				if err == nil {
					t.Errorf("GetPaths(%q) expected error, got nil", tt.instance)
				}
			} else {
				if err != nil {
					t.Errorf("GetPaths(%q) unexpected error: %v", tt.instance, err)
				}
			}
		})
	}
}

func TestDefaultInstance(t *testing.T) {
	inst := DefaultInstance("test")

	if inst.Version != CurrentInstanceVersion {
		t.Errorf("DefaultInstance().Version = %d, want %d", inst.Version, CurrentInstanceVersion)
	}
	if inst.Name != "test" {
		t.Errorf("DefaultInstance().Name = %q, want %q", inst.Name, "test")
	}
	if inst.CPUs != 2 {
		t.Errorf("DefaultInstance().CPUs = %d, want %d", inst.CPUs, 2)
	}
	if inst.Memory != 4096 {
		t.Errorf("DefaultInstance().Memory = %d, want %d", inst.Memory, 4096)
	}
	if inst.Base != "ubuntu-24.04" {
		t.Errorf("DefaultInstance().Base = %q, want %q", inst.Base, "ubuntu-24.04")
	}
	if inst.DNS.Upstream != "8.8.8.8:53" {
		t.Errorf("DefaultInstance().DNS.Upstream = %q, want %q", inst.DNS.Upstream, "8.8.8.8:53")
	}
	if inst.Disk != "20G" {
		t.Errorf("DefaultInstance().Disk = %q, want %q", inst.Disk, "20G")
	}
}

func TestDefaultUserForBase(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		expected string
	}{
		{"ubuntu base", "ubuntu-24.04", "ubuntu"},
		{"almalinux base", "almalinux-9", "almalinux"},
		{"almalinux-8 base", "almalinux-8", "almalinux"},
		{"rocky base", "rocky-9", "cloud-user"},
		{"centos base", "centos-8", "centos"},
		{"debian base", "debian-12", "debian"},
		{"unknown base defaults to ubuntu", "unknown-distro", "ubuntu"},
		{"empty base defaults to ubuntu", "", "ubuntu"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DefaultUserForBase(tt.base)
			if result != tt.expected {
				t.Errorf("DefaultUserForBase(%q) = %q, want %q", tt.base, result, tt.expected)
			}
		})
	}
}

func TestInstance_GetUser(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		base     string
		expected string
	}{
		{"default ubuntu base", "", "ubuntu-24.04", "ubuntu"},
		{"custom user", "root", "ubuntu-24.04", "root"},
		{"another custom user", "admin", "ubuntu-24.04", "admin"},
		{"almalinux base", "", "almalinux-9", "almalinux"},
		{"almalinux-8 base", "", "almalinux-8", "almalinux"},
		{"rocky base", "", "rocky-9", "cloud-user"},
		{"centos base", "", "centos-8", "centos"},
		{"debian base", "", "debian-12", "debian"},
		{"unknown base defaults to ubuntu", "", "unknown-distro", "ubuntu"},
		{"empty base defaults to ubuntu", "", "", "ubuntu"},
		{"custom user overrides almalinux default", "myuser", "almalinux-9", "myuser"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := &Instance{User: tt.user, Base: tt.base}
			result := inst.GetUser()
			if result != tt.expected {
				t.Errorf("GetUser() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetPaths_XDGEnvVars(t *testing.T) {
	mock := NewMockFileSystem()
	mock.EnvVars["XDG_DATA_HOME"] = "/custom/data"
	mock.EnvVars["XDG_RUNTIME_DIR"] = "/run/user/1000"
	// Mark the runtime directory as existing so it's used for sockets
	mock.Dirs["/run/user/1000"] = true
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	paths, err := GetPaths("test")
	if err != nil {
		t.Fatalf("GetPaths() error = %v", err)
	}

	if paths.Base != "/custom/data/abox" {
		t.Errorf("GetPaths().Base = %q, want %q", paths.Base, "/custom/data/abox")
	}
	if paths.DNSSocket != "/run/user/1000/abox-test-dns.sock" {
		t.Errorf("GetPaths().DNSSocket = %q, want %q", paths.DNSSocket, "/run/user/1000/abox-test-dns.sock")
	}
}

func TestDelete_WithMock(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Dirs["/home/testuser/.local/share/abox/instances/test"] = true
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte("version: 1\nname: test")
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	err := Delete("test")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify directory was removed
	if mock.Dirs["/home/testuser/.local/share/abox/instances/test"] {
		t.Error("Delete() should have removed directory")
	}
}

func TestLoad_ValidationRejectsInvalidUser(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 1
name: test
cpus: 2
memory: 4096
user: user$(whoami)
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("test")
	if err == nil {
		t.Error("Load() should reject config with invalid SSH user (command injection attempt)")
	}
}

func TestLoad_ValidationRejectsInvalidInstanceName(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 1
name: ../etc/passwd
cpus: 2
memory: 4096
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("test")
	if err == nil {
		t.Error("Load() should reject config with invalid instance name (path traversal attempt)")
	}
}

func TestLoad_ValidationRejectsInvalidMAC(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 1
name: test
cpus: 2
memory: 4096
mac_address: invalid-mac
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("test")
	if err == nil {
		t.Error("Load() should reject config with invalid MAC address")
	}
}

func TestLoad_ValidationRejectsInvalidDNSLogLevel(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 1
name: test
cpus: 2
memory: 4096
dns:
  log_level: "--help"
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("test")
	if err == nil {
		t.Error("Load() should reject config with invalid DNS log level (flag injection attempt)")
	}
	if !strings.Contains(err.Error(), "dns") || !strings.Contains(err.Error(), "log level") {
		t.Errorf("Load() error = %q, should mention dns and log level", err.Error())
	}
}

func TestLoad_ValidationRejectsInvalidHTTPLogLevel(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 1
name: test
cpus: 2
memory: 4096
http:
  log_level: "info; rm -rf /"
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("test")
	if err == nil {
		t.Error("Load() should reject config with invalid HTTP log level (command injection attempt)")
	}
	if !strings.Contains(err.Error(), "http") || !strings.Contains(err.Error(), "log level") {
		t.Errorf("Load() error = %q, should mention http and log level", err.Error())
	}
}

func TestLoad_ValidationAcceptsValidConfig(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 1
name: test
cpus: 2
memory: 4096
disk: 20G
user: ubuntu
mac_address: 52:54:00:ab:cd:ef
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	inst, _, err := Load("test")
	if err != nil {
		t.Fatalf("Load() unexpected error for valid config: %v", err)
	}
	if inst.Name != "test" {
		t.Errorf("Load().Name = %q, want %q", inst.Name, "test")
	}
	if inst.User != "ubuntu" {
		t.Errorf("Load().User = %q, want %q", inst.User, "ubuntu")
	}
}

func validInstance(name string) Instance {
	return Instance{Name: name, CPUs: 2, Memory: 4096, Disk: "20G"}
}

func TestInstance_Validate(t *testing.T) {
	tests := []struct {
		name    string
		inst    Instance
		wantErr bool
	}{
		{
			name:    "valid minimal",
			inst:    validInstance("test"),
			wantErr: false,
		},
		{
			name: "valid with user",
			inst: func() Instance { i := validInstance("test"); i.User = "ubuntu"; return i }(),
		},
		{
			name: "valid with mac",
			inst: func() Instance { i := validInstance("test"); i.MACAddress = "52:54:00:ab:cd:ef"; return i }(),
		},
		{
			name: "valid with dns log level",
			inst: func() Instance { i := validInstance("test"); i.DNS.LogLevel = "debug"; return i }(),
		},
		{
			name: "valid with http log level",
			inst: func() Instance { i := validInstance("test"); i.HTTP.LogLevel = "error"; return i }(),
		},
		{
			name: "valid with empty log levels",
			inst: validInstance("test"),
		},
		{
			name:    "invalid name",
			inst:    validInstance("../bad"),
			wantErr: true,
		},
		{
			name:    "invalid user",
			inst:    func() Instance { i := validInstance("test"); i.User = "user;whoami"; return i }(),
			wantErr: true,
		},
		{
			name:    "invalid mac",
			inst:    func() Instance { i := validInstance("test"); i.MACAddress = "not-a-mac"; return i }(),
			wantErr: true,
		},
		{
			name:    "invalid dns log level",
			inst:    func() Instance { i := validInstance("test"); i.DNS.LogLevel = "invalid"; return i }(),
			wantErr: true,
		},
		{
			name:    "invalid http log level",
			inst:    func() Instance { i := validInstance("test"); i.HTTP.LogLevel = "trace"; return i }(),
			wantErr: true,
		},
		{
			name:    "dns log level flag injection",
			inst:    func() Instance { i := validInstance("test"); i.DNS.LogLevel = "--help"; return i }(),
			wantErr: true,
		},
		{
			name:    "http log level command injection",
			inst:    func() Instance { i := validInstance("test"); i.HTTP.LogLevel = "info; rm -rf /"; return i }(),
			wantErr: true,
		},
		{
			name:    "zero cpus",
			inst:    func() Instance { i := validInstance("test"); i.CPUs = 0; return i }(),
			wantErr: true,
		},
		{
			name:    "zero memory",
			inst:    func() Instance { i := validInstance("test"); i.Memory = 0; return i }(),
			wantErr: true,
		},
		{
			name:    "negative cpus",
			inst:    func() Instance { i := validInstance("test"); i.CPUs = -1; return i }(),
			wantErr: true,
		},
		{
			name:    "excessive cpus",
			inst:    func() Instance { i := validInstance("test"); i.CPUs = 999; return i }(),
			wantErr: true,
		},
		{
			name:    "empty disk",
			inst:    func() Instance { i := validInstance("test"); i.Disk = ""; return i }(),
			wantErr: true,
		},
		{
			name:    "invalid disk format",
			inst:    func() Instance { i := validInstance("test"); i.Disk = "abc"; return i }(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inst.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Instance.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_RejectsMissingVersion(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
name: test
cpus: 2
memory: 4096
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("test")
	if err == nil {
		t.Error("Load() should reject config without version")
	}
	if !strings.Contains(err.Error(), "missing required 'version' field") {
		t.Errorf("Load() error = %q, want to contain 'missing required'", err.Error())
	}
}

func TestLoad_RejectsNewerVersion(t *testing.T) {
	mock := NewMockFileSystem()
	mock.Files["/home/testuser/.local/share/abox/instances/test/config.yaml"] = []byte(`
version: 999
name: test
cpus: 2
memory: 4096
`)
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	_, _, err := Load("test")
	if err == nil {
		t.Error("Load() should reject config with newer version")
	}
	if !strings.Contains(err.Error(), "newer than supported") {
		t.Errorf("Load() error = %q, want to contain 'newer than supported'", err.Error())
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
