package boxfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultBoxfile(t *testing.T) {
	box := DefaultBoxfile()

	if box.Version != CurrentBoxfileVersion {
		t.Errorf("DefaultBoxfile().Version = %d, want %d", box.Version, CurrentBoxfileVersion)
	}
	if box.CPUs != 2 {
		t.Errorf("DefaultBoxfile().CPUs = %d, want %d", box.CPUs, 2)
	}
	if box.Memory != 4096 {
		t.Errorf("DefaultBoxfile().Memory = %d, want %d", box.Memory, 4096)
	}
	if box.Disk != "20G" {
		t.Errorf("DefaultBoxfile().Disk = %q, want %q", box.Disk, "20G")
	}
	if box.Base != "ubuntu-24.04" {
		t.Errorf("DefaultBoxfile().Base = %q, want %q", box.Base, "ubuntu-24.04")
	}
	if box.User != "ubuntu" {
		t.Errorf("DefaultBoxfile().User = %q, want %q", box.User, "ubuntu")
	}
	if box.DNS.Upstream != "8.8.8.8:53" {
		t.Errorf("DefaultBoxfile().DNS.Upstream = %q, want %q", box.DNS.Upstream, "8.8.8.8:53")
	}
}

func TestCurrentBoxfileVersionConstant(t *testing.T) {
	if CurrentBoxfileVersion != 1 {
		t.Errorf("CurrentBoxfileVersion = %d, want 1", CurrentBoxfileVersion)
	}
}

func TestLoad_ValidBoxfile(t *testing.T) {
	dir := t.TempDir()
	boxfilePath := filepath.Join(dir, "abox.yaml")

	content := `version: 1
name: test-instance
cpus: 4
memory: 8192
`
	if err := os.WriteFile(boxfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	box, absDir, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if box.Version != 1 {
		t.Errorf("Load().Version = %d, want 1", box.Version)
	}
	if box.Name != "test-instance" {
		t.Errorf("Load().Name = %q, want %q", box.Name, "test-instance")
	}
	if box.CPUs != 4 {
		t.Errorf("Load().CPUs = %d, want %d", box.CPUs, 4)
	}
	if box.Memory != 8192 {
		t.Errorf("Load().Memory = %d, want %d", box.Memory, 8192)
	}
	if absDir != dir {
		t.Errorf("Load() absDir = %q, want %q", absDir, dir)
	}
}

func TestLoad_RejectsMissingVersion(t *testing.T) {
	dir := t.TempDir()
	boxfilePath := filepath.Join(dir, "abox.yaml")

	content := `name: test-instance
cpus: 2
memory: 4096
`
	if err := os.WriteFile(boxfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, _, err := Load(dir)
	if err == nil {
		t.Error("Load() should reject abox.yaml without version")
	}
	if !strings.Contains(err.Error(), "missing required 'version' field") {
		t.Errorf("Load() error = %q, want to contain 'missing required'", err.Error())
	}
}

func TestLoad_RejectsNewerVersion(t *testing.T) {
	dir := t.TempDir()
	boxfilePath := filepath.Join(dir, "abox.yaml")

	content := `version: 999
name: test-instance
cpus: 2
memory: 4096
`
	if err := os.WriteFile(boxfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, _, err := Load(dir)
	if err == nil {
		t.Error("Load() should reject abox.yaml with newer version")
	}
	if !strings.Contains(err.Error(), "newer than supported") {
		t.Errorf("Load() error = %q, want to contain 'newer than supported'", err.Error())
	}
}

func TestLoad_NotFound(t *testing.T) {
	dir := t.TempDir()

	_, _, err := Load(dir)
	if err == nil {
		t.Error("Load() should return error when abox.yaml not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Load() error = %q, want to contain 'not found'", err.Error())
	}
}

func TestValidate_OverridesTemplate(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid template", func(t *testing.T) {
		templatePath := filepath.Join(dir, "domain.xml.tmpl")
		tmpl := `<domain type="kvm"><name>{{.Name}}</name></domain>`
		if err := os.WriteFile(templatePath, []byte(tmpl), 0o644); err != nil {
			t.Fatal(err)
		}

		box := DefaultBoxfile()
		box.Name = "test"
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "domain.xml.tmpl"},
		}
		if err := box.Validate(dir); err != nil {
			t.Errorf("Validate() error = %v", err)
		}
	})

	t.Run("missing template file", func(t *testing.T) {
		box := DefaultBoxfile()
		box.Name = "test"
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "nonexistent.xml.tmpl"},
		}
		err := box.Validate(dir)
		if err == nil {
			t.Fatal("Validate() should return error for missing template file")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention 'not found': %v", err)
		}
	})

	t.Run("invalid template syntax passes boxfile validation", func(t *testing.T) {
		// Boxfile validation only checks that the file exists and is readable.
		// Content validation (template syntax) is deferred to the backend layer.
		templatePath := filepath.Join(dir, "bad.xml.tmpl")
		if err := os.WriteFile(templatePath, []byte(`{{.Name}`), 0o644); err != nil {
			t.Fatal(err)
		}

		box := DefaultBoxfile()
		box.Name = "test"
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "bad.xml.tmpl"},
		}
		if err := box.Validate(dir); err != nil {
			t.Errorf("Validate() should not check template syntax: %v", err)
		}
	})

	t.Run("no overrides is valid", func(t *testing.T) {
		box := DefaultBoxfile()
		box.Name = "test"
		if err := box.Validate(dir); err != nil {
			t.Errorf("Validate() should succeed with no overrides: %v", err)
		}
	})
}

func TestResolveOverridePath(t *testing.T) {
	dir := t.TempDir()

	t.Run("relative path", func(t *testing.T) {
		box := DefaultBoxfile()
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "domain.xml.tmpl"},
		}
		got, err := box.ResolveOverridePath("libvirt", "template", dir)
		if err != nil {
			t.Fatalf("ResolveOverridePath() error = %v", err)
		}
		want := filepath.Join(dir, "domain.xml.tmpl")
		if got != want {
			t.Errorf("ResolveOverridePath() = %q, want %q", got, want)
		}
	})

	t.Run("empty returns empty", func(t *testing.T) {
		box := DefaultBoxfile()
		got, err := box.ResolveOverridePath("libvirt", "template", dir)
		if err != nil {
			t.Fatalf("ResolveOverridePath() error = %v", err)
		}
		if got != "" {
			t.Errorf("ResolveOverridePath() = %q, want empty", got)
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		box := DefaultBoxfile()
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "../../../etc/shadow"},
		}
		_, err := box.ResolveOverridePath("libvirt", "template", dir)
		if err == nil {
			t.Fatal("ResolveOverridePath() should reject path traversal")
		}
	})

	t.Run("absolute path allowed", func(t *testing.T) {
		box := DefaultBoxfile()
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "/opt/templates/domain.xml.tmpl"},
		}
		got, err := box.ResolveOverridePath("libvirt", "template", dir)
		if err != nil {
			t.Fatalf("ResolveOverridePath() error = %v", err)
		}
		if got != "/opt/templates/domain.xml.tmpl" {
			t.Errorf("ResolveOverridePath() = %q, want %q", got, "/opt/templates/domain.xml.tmpl")
		}
	})
}

func TestLoadOverrideContent(t *testing.T) {
	dir := t.TempDir()

	t.Run("returns content when template exists", func(t *testing.T) {
		tmpl := `<domain type="kvm"><name>{{.Name}}</name></domain>`
		templatePath := filepath.Join(dir, "domain.xml.tmpl")
		if err := os.WriteFile(templatePath, []byte(tmpl), 0o644); err != nil {
			t.Fatal(err)
		}

		box := DefaultBoxfile()
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "domain.xml.tmpl"},
		}
		got, err := box.LoadOverrideContent("libvirt", "template", dir)
		if err != nil {
			t.Fatalf("LoadOverrideContent() error = %v", err)
		}
		if got != tmpl {
			t.Errorf("LoadOverrideContent() = %q, want %q", got, tmpl)
		}
	})

	t.Run("returns empty when no template configured", func(t *testing.T) {
		box := DefaultBoxfile()
		got, err := box.LoadOverrideContent("libvirt", "template", dir)
		if err != nil {
			t.Fatalf("LoadOverrideContent() error = %v", err)
		}
		if got != "" {
			t.Errorf("LoadOverrideContent() = %q, want empty", got)
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		box := DefaultBoxfile()
		box.Overrides = map[string]map[string]string{
			"libvirt": {"template": "nonexistent.xml.tmpl"},
		}
		_, err := box.LoadOverrideContent("libvirt", "template", dir)
		if err == nil {
			t.Fatal("LoadOverrideContent() should return error for missing file")
		}
	})
}

func TestValidate_ResourceLimits(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		cpus    int
		memory  int
		disk    string
		wantErr string
	}{
		{name: "valid defaults", cpus: 2, memory: 4096, disk: "20G"},
		{name: "negative CPUs", cpus: -1, memory: 4096, disk: "20G", wantErr: "invalid resource limits"},
		{name: "zero CPUs", cpus: 0, memory: 4096, disk: "20G", wantErr: "invalid resource limits"},
		{name: "excessive CPUs", cpus: 200, memory: 4096, disk: "20G", wantErr: "invalid resource limits"},
		{name: "zero memory", cpus: 2, memory: 0, disk: "20G", wantErr: "invalid resource limits"},
		{name: "invalid disk format", cpus: 2, memory: 4096, disk: "abc", wantErr: "invalid disk size"},
		{name: "empty disk uses default", cpus: 2, memory: 4096, disk: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			box := DefaultBoxfile()
			box.Name = "test"
			box.CPUs = tt.cpus
			box.Memory = tt.memory
			if tt.disk != "" {
				box.Disk = tt.disk
			}
			err := box.Validate(dir)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	dir := t.TempDir()
	boxfilePath := filepath.Join(dir, "abox.yaml")

	// Minimal valid boxfile - should use defaults for missing fields
	content := `version: 1
name: minimal
`
	if err := os.WriteFile(boxfilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	box, _, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check defaults are applied
	if box.CPUs != 2 {
		t.Errorf("Load().CPUs = %d, want default 2", box.CPUs)
	}
	if box.Memory != 4096 {
		t.Errorf("Load().Memory = %d, want default 4096", box.Memory)
	}
	if box.Disk != "20G" {
		t.Errorf("Load().Disk = %q, want default %q", box.Disk, "20G")
	}
	if box.Base != "ubuntu-24.04" {
		t.Errorf("Load().Base = %q, want default %q", box.Base, "ubuntu-24.04")
	}
}
