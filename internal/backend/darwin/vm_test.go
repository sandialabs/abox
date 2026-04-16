//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/sandialabs/abox/internal/config"
)

func TestGenerateUUID(t *testing.T) {
	uuid, err := generateUUID()
	if err != nil {
		t.Fatalf("generateUUID() error: %v", err)
	}

	// UUID v4 format: 8-4-4-4-12 hex digits
	pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	matched, err := regexp.MatchString(pattern, uuid)
	if err != nil {
		t.Fatalf("regexp error: %v", err)
	}
	if !matched {
		t.Errorf("generateUUID() = %q, does not match UUID v4 pattern", uuid)
	}

	// Two calls should produce different UUIDs.
	uuid2, err := generateUUID()
	if err != nil {
		t.Fatalf("generateUUID() second call error: %v", err)
	}
	if uuid == uuid2 {
		t.Errorf("generateUUID() produced duplicate: %q", uuid)
	}
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		name string
		mac  string
		want string
	}{
		{
			name: "already_normalized",
			mac:  "2:ab:0:a:b:c",
			want: "2:ab:0:a:b:c",
		},
		{
			name: "leading_zeros",
			mac:  "02:AB:00:0A:0B:0C",
			want: "2:ab:0:a:b:c",
		},
		{
			name: "mixed",
			mac:  "02:ab:00:ff:01:10",
			want: "2:ab:0:ff:1:10",
		},
		{
			name: "all_zeros",
			mac:  "00:00:00:00:00:00",
			want: "0:0:0:0:0:0",
		},
		{
			name: "no_leading_zeros",
			mac:  "ff:ee:dd:cc:bb:aa",
			want: "ff:ee:dd:cc:bb:aa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeMAC(tt.mac)
			if got != tt.want {
				t.Errorf("normalizeMAC(%q) = %q, want %q", tt.mac, got, tt.want)
			}
		})
	}
}

func TestBackendUUID(t *testing.T) {
	tests := []struct {
		name string
		inst *config.Instance
		want string
	}{
		{
			name: "nil_map",
			inst: &config.Instance{},
			want: "",
		},
		{
			name: "missing_key",
			inst: &config.Instance{BackendConfig: map[string]any{"other": "val"}},
			want: "",
		},
		{
			name: "wrong_type",
			inst: &config.Instance{BackendConfig: map[string]any{"uuid": 123}},
			want: "",
		},
		{
			name: "valid",
			inst: &config.Instance{BackendConfig: map[string]any{"uuid": "abc-123"}},
			want: "abc-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backendUUID(tt.inst)
			if got != tt.want {
				t.Errorf("backendUUID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBackendRESTPort(t *testing.T) {
	tests := []struct {
		name string
		inst *config.Instance
		want int
	}{
		{
			name: "nil_map",
			inst: &config.Instance{},
			want: 0,
		},
		{
			name: "missing_key",
			inst: &config.Instance{BackendConfig: map[string]any{"other": "val"}},
			want: 0,
		},
		{
			name: "int_value",
			inst: &config.Instance{BackendConfig: map[string]any{"rest_port": 12345}},
			want: 12345,
		},
		{
			name: "float64_value_from_yaml",
			inst: &config.Instance{BackendConfig: map[string]any{"rest_port": float64(12345)}},
			want: 12345,
		},
		{
			name: "wrong_type",
			inst: &config.Instance{BackendConfig: map[string]any{"rest_port": "bad"}},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backendRESTPort(tt.inst)
			if got != tt.want {
				t.Errorf("backendRESTPort() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRestfulURI(t *testing.T) {
	tests := []struct {
		name string
		inst *config.Instance
		want string
	}{
		{
			name: "no_port",
			inst: &config.Instance{},
			want: "",
		},
		{
			name: "with_port",
			inst: &config.Instance{BackendConfig: map[string]any{"rest_port": 8080}},
			want: "tcp://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := restfulURI(tt.inst)
			if got != tt.want {
				t.Errorf("restfulURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVfkitPIDFile(t *testing.T) {
	pidFile := vfkitPIDFile("myvm")
	if !filepath.IsAbs(pidFile) {
		t.Errorf("vfkitPIDFile() should return absolute path, got %q", pidFile)
	}
	if filepath.Base(pidFile) != "abox-myvm-vfkit.pid" {
		t.Errorf("vfkitPIDFile() basename = %q, want %q", filepath.Base(pidFile), "abox-myvm-vfkit.pid")
	}
}

func TestBuildVMConfig(t *testing.T) {
	inst := &config.Instance{
		Name:          "testvm",
		CPUs:          4,
		Memory:        8192,
		MACAddress:    "02:ab:00:11:22:33",
		BackendConfig: map[string]any{"rest_port": 9999},
	}

	// Create a temp dir to simulate cloud-init ISO existence.
	tmpDir := t.TempDir()
	cloudInitISO := filepath.Join(tmpDir, "cidata.iso")
	logsDir := filepath.Join(tmpDir, "logs")
	_ = os.MkdirAll(logsDir, 0o755)

	paths := &config.Paths{
		Disk:         filepath.Join(tmpDir, "disk.raw"),
		CloudInitISO: cloudInitISO,
		LogsDir:      logsDir,
	}

	t.Run("without_cloud_init_iso", func(t *testing.T) {
		cfg := buildVMConfig(inst, paths)
		if cfg.Name != "testvm" {
			t.Errorf("Name = %q, want %q", cfg.Name, "testvm")
		}
		if cfg.CPUs != 4 {
			t.Errorf("CPUs = %d, want %d", cfg.CPUs, 4)
		}
		if cfg.MemoryMB != 8192 {
			t.Errorf("MemoryMB = %d, want %d", cfg.MemoryMB, 8192)
		}
		if cfg.CloudInitISO != "" {
			t.Errorf("CloudInitISO should be empty when file doesn't exist, got %q", cfg.CloudInitISO)
		}
		if cfg.RESTfulURI != "tcp://localhost:9999" {
			t.Errorf("RESTfulURI = %q, want %q", cfg.RESTfulURI, "tcp://localhost:9999")
		}
	})

	t.Run("with_cloud_init_iso", func(t *testing.T) {
		// Create the ISO file.
		if err := os.WriteFile(cloudInitISO, []byte("fake"), 0o644); err != nil {
			t.Fatalf("create fake ISO: %v", err)
		}
		defer os.Remove(cloudInitISO)

		cfg := buildVMConfig(inst, paths)
		if cfg.CloudInitISO != cloudInitISO {
			t.Errorf("CloudInitISO = %q, want %q", cfg.CloudInitISO, cloudInitISO)
		}
	})
}

func TestParseARPOutput(t *testing.T) {
	arpOutput := `? (192.168.64.1) at aa:bb:cc:dd:ee:ff on bridge100 ifscope [bridge]
? (192.168.64.3) at 2:ab:0:11:22:33 on bridge100 ifscope [ethernet]
? (192.168.64.5) at a:b:c:d:e:f on bridge100 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on bridge100 ifscope permanent [ethernet]`

	tests := []struct {
		name    string
		mac     string
		wantIP  string
		wantErr bool
	}{
		{
			name:   "found_with_leading_zeros",
			mac:    "02:AB:00:11:22:33",
			wantIP: "192.168.64.3",
		},
		{
			name:   "found_already_normalized",
			mac:    "2:ab:0:11:22:33",
			wantIP: "192.168.64.3",
		},
		{
			name:   "found_short_octets",
			mac:    "0a:0b:0c:0d:0e:0f",
			wantIP: "192.168.64.5",
		},
		{
			name:    "not_found",
			mac:     "ff:ff:ff:ff:ff:ff",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := parseARPOutput(arpOutput, tt.mac)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseARPOutput() expected error, got ip=%q", ip)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseARPOutput() error: %v", err)
			}
			if ip != tt.wantIP {
				t.Errorf("parseARPOutput() = %q, want %q", ip, tt.wantIP)
			}
		})
	}
}

func TestParseARPOutput_EmptyOutput(t *testing.T) {
	_, err := parseARPOutput("", "02:ab:00:11:22:33")
	if err == nil {
		t.Error("parseARPOutput() with empty output should return error")
	}
}
