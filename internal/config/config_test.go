package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/sandialabs/abox/internal/privilege"
)

func TestGenerateBridgeName(t *testing.T) {
	// Every (uid, name) hashes to "abx-<11 hex>" = 15 chars regardless of name
	// length, staying within the Linux IFNAMSIZ limit and passing
	// privilege.ValidateBridgeName (which the privilege helper applies). The
	// prefix must stay disjoint from the legacy "abox-"/"ab-" namespace so the
	// helper's legacy teardown leniency can never target a per-user bridge.
	instances := []string{
		"dev",
		"myinstance",
		"verylonginstancename",
		"a12345678901234567890123456789012345678901234567890123456789012", // 63 chars
	}
	for _, instance := range instances {
		t.Run(instance, func(t *testing.T) {
			got := GenerateBridgeName(1000, instance)
			if len(got) != 15 {
				t.Errorf("GenerateBridgeName(1000, %q) = %q (len=%d), want len=15", instance, got, len(got))
			}
			if !strings.HasPrefix(got, "abx-") {
				t.Errorf("GenerateBridgeName(1000, %q) = %q, want %q prefix", instance, got, "abx-")
			}
			if strings.HasPrefix(LegacyBridgeName(instance), "abx-") {
				t.Errorf("LegacyBridgeName(%q) collides with the per-user abx- namespace", instance)
			}
			if err := privilege.ValidateBridgeName(got); err != nil {
				t.Errorf("GenerateBridgeName(1000, %q) = %q, fails ValidateBridgeName: %v", instance, got, err)
			}
		})
	}
}

func TestGenerateBridgeName_Deterministic(t *testing.T) {
	// Same (uid, name) always produces the same output.
	if GenerateBridgeName(1000, "verylonginstancename") != GenerateBridgeName(1000, "verylonginstancename") {
		t.Error("GenerateBridgeName not deterministic")
	}
}

func TestGenerateBridgeName_UniqueHashes(t *testing.T) {
	// Different names produce different bridges.
	if GenerateBridgeName(1000, "inst1") == GenerateBridgeName(1000, "inst2") {
		t.Error("different names produced same bridge")
	}
	// Same name under DIFFERENT uids produces different bridges — the core
	// cross-user collision fix.
	if GenerateBridgeName(1000, "dev") == GenerateBridgeName(2000, "dev") {
		t.Error("same instance name under different uids produced same bridge (collision not prevented)")
	}
}

func TestLegacyBridgeName(t *testing.T) {
	// The legacy derivation preserves the old name-only scheme, used to recognize
	// and tear down objects created by older abox versions (and by the macOS
	// backends, which keep it).
	if got := LegacyBridgeName("dev"); got != "abox-dev" {
		t.Errorf("LegacyBridgeName(%q) = %q, want %q", "dev", got, "abox-dev")
	}
	long := LegacyBridgeName("verylonginstancename")
	if len(long) != 15 || !strings.HasPrefix(long, "ab-") {
		t.Errorf("LegacyBridgeName(long) = %q, want 15-char ab- hash", long)
	}
}

func TestResolvedNames(t *testing.T) {
	uid := os.Getuid()

	// An instance whose recorded bridge matches the current (uid, name)
	// derivation is on the per-user scheme and resolves per-user names.
	current := &Instance{Name: "dev", Bridge: GenerateBridgeName(uid, "dev")}
	if !current.UsesCurrentNames() {
		t.Error("instance with uid-derived bridge should use current names")
	}
	if got, want := current.ResolvedVMName(), DomainNameFor(uid, "dev"); got != want {
		t.Errorf("ResolvedVMName() = %q, want %q", got, want)
	}
	if got, want := current.ResolvedFilterName(), FilterNameFor(uid, "dev"); got != want {
		t.Errorf("ResolvedFilterName() = %q, want %q", got, want)
	}

	// A legacy instance (name-only bridge, created by an older abox) keeps
	// resolving the legacy names until its next start upgrades it.
	legacy := &Instance{Name: "dev", Bridge: "abox-dev"}
	if legacy.UsesCurrentNames() {
		t.Error("instance with legacy bridge should not use current names")
	}
	if got := legacy.ResolvedVMName(); got != "abox-dev" {
		t.Errorf("legacy ResolvedVMName() = %q, want %q", got, "abox-dev")
	}
	if got := legacy.ResolvedFilterName(); got != "abox-dev-traffic" {
		t.Errorf("legacy ResolvedFilterName() = %q, want %q", got, "abox-dev-traffic")
	}

	// A bridge recorded under a DIFFERENT uid (copied instance dir) is not
	// "current" either — the copy must be re-created under the new owner's names
	// rather than silently driving the original owner's objects.
	foreign := &Instance{Name: "dev", Bridge: GenerateBridgeName(uid+1, "dev")}
	if foreign.UsesCurrentNames() {
		t.Error("bridge recorded under another uid must not count as current")
	}
}

func TestDomainAndFilterNameFor(t *testing.T) {
	if got := DomainNameFor(1000, "dev"); got != "abox-1000-dev" {
		t.Errorf("DomainNameFor = %q, want abox-1000-dev", got)
	}
	if got := FilterNameFor(1000, "dev"); got != "abox-1000-dev-traffic" {
		t.Errorf("FilterNameFor = %q, want abox-1000-dev-traffic", got)
	}
	if got := LegacyDomainName("dev"); got != "abox-dev" {
		t.Errorf("LegacyDomainName = %q, want abox-dev", got)
	}
	if got := LegacyFilterName("dev"); got != "abox-dev-traffic" {
		t.Errorf("LegacyFilterName = %q, want abox-dev-traffic", got)
	}
}

func TestLoad_WithMock(t *testing.T) {
	skipOnWindows(t)
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
	skipOnWindows(t)
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
	skipOnWindows(t)
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

func TestUsedInstanceSubnets_WithMock(t *testing.T) {
	skipOnWindows(t)
	const base = "/home/testuser/.local/share/abox/instances"
	mock := NewMockFileSystem()
	mock.DirEntries[base] = []os.DirEntry{
		&mockDirEntry{nameVal: "dev", isDirVal: true},
		&mockDirEntry{nameVal: "prod", isDirVal: true},
		&mockDirEntry{nameVal: "broken", isDirVal: true},
	}
	mock.Files[base+"/dev/config.yaml"] = []byte("version: 1\nname: dev\ncpus: 2\nmemory: 2048\ndisk: 20G\nsubnet: 10.10.10.0/24")
	mock.Files[base+"/prod/config.yaml"] = []byte("version: 1\nname: prod\ncpus: 2\nmemory: 2048\ndisk: 20G\nsubnet: 10.10.20.0/24")
	// broken: wrong config version -> Load errors -> must be skipped (not fatal),
	// and its subnet must NOT be recorded as used.
	mock.Files[base+"/broken/config.yaml"] = []byte("version: 999\nname: broken\nsubnet: 10.10.99.0/24")
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	used, err := UsedInstanceSubnets()
	if err != nil {
		t.Fatalf("UsedInstanceSubnets() error = %v", err)
	}
	if !used["10.10.10.0/24"] || !used["10.10.20.0/24"] {
		t.Errorf("dev+prod subnets should be marked used, got %v", used)
	}
	if used["10.10.99.0/24"] {
		t.Error("subnet of an unreadable instance config must not be marked used")
	}
	if len(used) != 2 {
		t.Errorf("expected exactly 2 used subnets (broken skipped), got %d: %v", len(used), used)
	}
}

func TestUsedInstanceSubnets_EmptyDir(t *testing.T) {
	mock := NewMockFileSystem()
	mock.ReadDirErr = os.ErrNotExist
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	used, err := UsedInstanceSubnets()
	if err != nil {
		t.Fatalf("UsedInstanceSubnets() error = %v", err)
	}
	if len(used) != 0 {
		t.Errorf("no instances should yield an empty set, got %v", used)
	}
}

func TestGetPaths_PathTraversal(t *testing.T) {
	// Pin TMPDIR: with the mocked (empty) filesystem the runtime dir "doesn't
	// exist", so GetPaths provisions the per-uid fallback on the REAL filesystem
	// (deliberately outside the fsys seam) — keep that inside the test sandbox.
	t.Setenv("TMPDIR", t.TempDir())
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
	if inst.DNS.Upstream != "" {
		t.Errorf("DefaultInstance().DNS.Upstream = %q, want %q (empty = host system resolver)", inst.DNS.Upstream, "")
	}
	if inst.Disk != "20G" {
		t.Errorf("DefaultInstance().Disk = %q, want %q", inst.Disk, "20G")
	}
	if inst.HTTP.MaxConnections != DefaultHTTPMaxConnections {
		t.Errorf("DefaultInstance().HTTP.MaxConnections = %d, want %d", inst.HTTP.MaxConnections, DefaultHTTPMaxConnections)
	}
}

func TestValidate_MaxConnections(t *testing.T) {
	inst := DefaultInstance("test")
	inst.Subnet = "10.10.10.0/24"
	inst.Gateway = "10.10.10.1"

	// Negative is invalid.
	inst.HTTP.MaxConnections = -1
	if err := inst.Validate(); err == nil {
		t.Error("expected error for negative HTTP.MaxConnections, got nil")
	}

	// Zero is allowed (legacy/unset; resolved to default at startup).
	inst.HTTP.MaxConnections = 0
	if err := inst.Validate(); err != nil {
		t.Errorf("unexpected error for zero (unset) HTTP.MaxConnections: %v", err)
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
	skipOnWindows(t)
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

func TestRuntimeDir(t *testing.T) {
	skipOnWindows(t)
	tests := []struct {
		name     string
		xdg      string // value of XDG_RUNTIME_DIR ("" = unset)
		existing string // directory to register as existing ("" = none)
		want     string
		wantErr  bool
	}{
		{
			// WSL sets XDG_RUNTIME_DIR with a trailing slash; RuntimeDir must
			// normalize it. Registering the cleaned key as the existing dir also
			// proves Clean runs before Stat (a raw Stat would miss the mock key).
			name:     "trailing slash is cleaned",
			xdg:      "/run/user/1000/",
			existing: "/run/user/1000",
			want:     "/run/user/1000",
		},
		{
			name:     "already clean returned unchanged",
			xdg:      "/run/user/1000",
			existing: "/run/user/1000",
			want:     "/run/user/1000",
		},
		{
			// XDG unset and the /run/user/<uid> fallback does not exist.
			name:    "missing fallback errors",
			xdg:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockFileSystem()
			if tt.xdg != "" {
				mock.EnvVars["XDG_RUNTIME_DIR"] = tt.xdg
			}
			if tt.existing != "" {
				mock.Dirs[tt.existing] = true
			}
			prev := SetFileSystem(mock)
			defer SetFileSystem(prev)

			got, err := RuntimeDir()
			if (err != nil) != tt.wantErr {
				t.Fatalf("RuntimeDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("RuntimeDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRuntimeDir_SocketPathValid guards the WSL regression end-to-end: a socket
// path built from a trailing-slash runtime dir (via filepath.Join, as in
// factory.PrivilegeClient) must satisfy the setuid helper's ValidateSocketPath.
func TestRuntimeDir_SocketPathValid(t *testing.T) {
	skipOnWindows(t)
	mock := NewMockFileSystem()
	mock.EnvVars["XDG_RUNTIME_DIR"] = "/run/user/1000/"
	mock.Dirs["/run/user/1000"] = true
	prev := SetFileSystem(mock)
	defer SetFileSystem(prev)

	dir, err := RuntimeDir()
	if err != nil {
		t.Fatalf("RuntimeDir() error = %v", err)
	}
	socketPath := filepath.Join(dir, "abox-privilege-deadbeef.sock")
	if err := privilege.ValidateSocketPath(socketPath); err != nil {
		t.Errorf("ValidateSocketPath(%q) = %v, want nil", socketPath, err)
	}
}

func TestDelete_WithMock(t *testing.T) {
	skipOnWindows(t)
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
	skipOnWindows(t)
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
	skipOnWindows(t)
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
	skipOnWindows(t)
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
	skipOnWindows(t)
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
	skipOnWindows(t)
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
	skipOnWindows(t)
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
			// 1 and 65535 are the inclusive bounds of the accepted range.
			name: "valid with allowed ports at range bounds",
			inst: func() Instance { i := validInstance("test"); i.HTTP.AllowedPorts = []int{1, 443, 65535}; return i }(),
		},
		{
			name: "valid with empty allowed ports",
			inst: func() Instance { i := validInstance("test"); i.HTTP.AllowedPorts = nil; return i }(),
		},
		{
			name: "valid with allow_private_targets cidr",
			inst: func() Instance {
				i := validInstance("test")
				i.HTTP.AllowPrivateTargets = []string{"10.0.0.0/8", "192.168.0.0/16"}
				return i
			}(),
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
			name:    "allowed port zero",
			inst:    func() Instance { i := validInstance("test"); i.HTTP.AllowedPorts = []int{0}; return i }(),
			wantErr: true,
		},
		{
			name:    "allowed port negative",
			inst:    func() Instance { i := validInstance("test"); i.HTTP.AllowedPorts = []int{-1}; return i }(),
			wantErr: true,
		},
		{
			name:    "allowed port above range",
			inst:    func() Instance { i := validInstance("test"); i.HTTP.AllowedPorts = []int{65536}; return i }(),
			wantErr: true,
		},
		{
			// The loop must check every entry, not just the first.
			name:    "allowed port invalid in trailing position",
			inst:    func() Instance { i := validInstance("test"); i.HTTP.AllowedPorts = []int{443, 99999}; return i }(),
			wantErr: true,
		},
		{
			name: "invalid allow_private_targets cidr",
			inst: func() Instance {
				i := validInstance("test")
				i.HTTP.AllowPrivateTargets = []string{"not-a-cidr"}
				return i
			}(),
			wantErr: true,
		},
		{
			// A bare IP is not a CIDR block; net.ParseCIDR must reject it.
			name: "allow_private_targets bare ip",
			inst: func() Instance {
				i := validInstance("test")
				i.HTTP.AllowPrivateTargets = []string{"10.0.0.1"}
				return i
			}(),
			wantErr: true,
		},
		{
			name: "invalid allow_private_targets cidr in trailing position",
			inst: func() Instance {
				i := validInstance("test")
				i.HTTP.AllowPrivateTargets = []string{"10.0.0.0/8", "999.0.0.0/8"}
				return i
			}(),
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
	skipOnWindows(t)
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
	skipOnWindows(t)
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

// TestPrivateRuntimeDir_FallbackCreatesPerUIDDir: with no usable runtime dir,
// the fallback is a per-uid 0700 directory under the system temp dir — never
// the shared temp dir itself, where two users' same-named instances would
// collide on socket filenames.
func TestPrivateRuntimeDir_FallbackCreatesPerUIDDir(t *testing.T) {
	skipOnWindows(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// Point XDG at a nonexistent dir so RuntimeDir() fails and the fallback runs.
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tmp, "no-such-dir"))

	dir, err := PrivateRuntimeDir()
	if err != nil {
		t.Fatalf("PrivateRuntimeDir: %v", err)
	}
	want := filepath.Join(tmp, fmt.Sprintf("abox-%d", os.Getuid()))
	if dir != want {
		t.Fatalf("PrivateRuntimeDir = %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat fallback dir: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Errorf("fallback dir mode = %v, want 0700 directory", info.Mode())
	}
}

// TestPrivateRuntimeDir_RefusesSquattedFallback: a pre-existing symlink or
// overly-permissive directory at the predictable fallback name must be a hard
// error, not silently used (the squat would hand sockets to another user).
func TestPrivateRuntimeDir_RefusesSquattedFallback(t *testing.T) {
	skipOnWindows(t)

	t.Run("symlink", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tmp, "no-such-dir"))
		target := filepath.Join(tmp, "elsewhere")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(tmp, fmt.Sprintf("abox-%d", os.Getuid()))); err != nil {
			t.Fatal(err)
		}
		if _, err := PrivateRuntimeDir(); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("PrivateRuntimeDir = %v, want symlink refusal", err)
		}
	})

	t.Run("group-other-accessible", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tmp, "no-such-dir"))
		squat := filepath.Join(tmp, fmt.Sprintf("abox-%d", os.Getuid()))
		if err := os.Mkdir(squat, 0o755); err != nil {
			t.Fatal(err)
		}
		// Mkdir applies umask; force the permissive mode explicitly.
		if err := os.Chmod(squat, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := PrivateRuntimeDir(); err == nil || !strings.Contains(err.Error(), "accessible to other users") {
			t.Fatalf("PrivateRuntimeDir = %v, want permission refusal", err)
		}
	})
}

// TestGetPaths_SquattedFallbackDegrades: a squatted per-uid fallback must not
// fail GetPaths — path-only consumers (list, remove's cleanup, status) keep
// working on still-computed paths — while the error is recorded in
// RuntimeDirErr for the socket-binding consumers to enforce.
func TestGetPaths_SquattedFallbackDegrades(t *testing.T) {
	skipOnWindows(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tmp, "no-such-dir"))
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	squat := filepath.Join(tmp, fmt.Sprintf("abox-%d", os.Getuid()))
	if err := os.Mkdir(squat, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(squat, 0o755); err != nil {
		t.Fatal(err)
	}

	paths, err := GetPaths("dev")
	if err != nil {
		t.Fatalf("GetPaths must degrade, not fail, on a squatted fallback: %v", err)
	}
	if paths.RuntimeDirErr == nil {
		t.Fatal("GetPaths().RuntimeDirErr = nil, want the squat error recorded")
	}
	if !strings.Contains(paths.RuntimeDirErr.Error(), "accessible to other users") {
		t.Errorf("RuntimeDirErr = %v, want the squat refusal", paths.RuntimeDirErr)
	}
	if paths.DNSSocket == "" || paths.Config == "" {
		t.Errorf("degraded Paths must still be fully computed; DNSSocket=%q Config=%q", paths.DNSSocket, paths.Config)
	}
}

// TestPrivateRuntimeDir_PrefersRuntimeDir: when the per-user runtime dir
// exists, it is used directly and no fallback dir is created.
func TestPrivateRuntimeDir_PrefersRuntimeDir(t *testing.T) {
	skipOnWindows(t)
	tmp := t.TempDir()
	runtime := filepath.Join(tmp, "runtime")
	if err := os.Mkdir(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	t.Setenv("TMPDIR", filepath.Join(tmp, "tmp-unused"))

	dir, err := PrivateRuntimeDir()
	if err != nil {
		t.Fatalf("PrivateRuntimeDir: %v", err)
	}
	if dir != runtime {
		t.Errorf("PrivateRuntimeDir = %q, want the runtime dir %q", dir, runtime)
	}
}
