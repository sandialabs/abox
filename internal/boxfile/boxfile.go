// Package boxfile provides parsing and validation for abox.yaml configuration files.
package boxfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/tetragon/policy"
	"github.com/sandialabs/abox/internal/validation"
)

// CurrentBoxfileVersion is the current version of the abox.yaml format.
const CurrentBoxfileVersion = 1

// BoxfileDNS holds DNS-related configuration in abox.yaml.
type BoxfileDNS struct {
	Upstream string `yaml:"upstream,omitempty"` // upstream DNS server
}

// BoxfileMonitor holds monitoring-related configuration in abox.yaml.
type BoxfileMonitor struct {
	Enabled     bool     `yaml:"enabled,omitempty"`      // enable Tetragon monitoring via virtio-serial
	Version     string   `yaml:"version,omitempty"`      // Tetragon version to use (empty = latest)
	KprobeMulti *bool    `yaml:"kprobe_multi,omitempty"` // enable BPF kprobe_multi attachment (default: false)
	Kprobes     []string `yaml:"kprobes,omitempty"`      // curated kprobe names (nil = all defaults); mutually exclusive with Policies
	Policies    []string `yaml:"policies,omitempty"`     // paths to custom TracingPolicy YAML files; mutually exclusive with Kprobes
}

// BoxfileHTTP holds HTTP proxy-related configuration in abox.yaml.
type BoxfileHTTP struct {
	MITM *bool `yaml:"mitm,omitempty"` // Enable TLS MITM (default: true). Pointer to distinguish unset from false.
}

// Boxfile represents the abox.yaml declarative configuration.
type Boxfile struct {
	Version   int                          `yaml:"version"`
	Name      string                       `yaml:"name"`
	CPUs      int                          `yaml:"cpus"`
	Memory    int                          `yaml:"memory"`
	Disk      string                       `yaml:"disk"`
	Base      string                       `yaml:"base"`
	User      string                       `yaml:"user"`
	Subnet    string                       `yaml:"subnet"`
	Provision []string                     `yaml:"provision"`
	Overlay   string                       `yaml:"overlay"`
	Allowlist []string                     `yaml:"allowlist,omitempty"` // domain allowlist (shared by DNS and HTTP filters)
	DNS       BoxfileDNS                   `yaml:"dns,omitempty"`
	HTTP      BoxfileHTTP                  `yaml:"http,omitempty"`      // HTTP proxy configuration
	Monitor   BoxfileMonitor               `yaml:"monitor,omitempty"`   // Tetragon monitoring configuration
	Overrides map[string]map[string]string `yaml:"overrides,omitempty"` // backend-specific overrides (e.g., overrides.libvirt.template)
}

// DefaultBoxfile returns a Boxfile with default values.
func DefaultBoxfile() *Boxfile {
	mitmDefault := true
	return &Boxfile{
		Version: CurrentBoxfileVersion,
		CPUs:    2,
		Memory:  4096,
		Disk:    config.DefaultDisk,
		Base:    config.DefaultBase,
		User:    "ubuntu",
		DNS: BoxfileDNS{
			Upstream: config.DefaultUpstream,
		},
		HTTP: BoxfileHTTP{
			MITM: &mitmDefault,
		},
	}
}

// GetKprobeMulti returns whether kprobe_multi is enabled, defaulting to false if not set.
func (b *Boxfile) GetKprobeMulti() bool {
	if b.Monitor.KprobeMulti != nil {
		return *b.Monitor.KprobeMulti
	}
	return false // default: disabled for reliability
}

// GetMITM returns whether MITM is enabled, defaulting to true if not set.
func (b *Boxfile) GetMITM() bool {
	if b.HTTP.MITM == nil {
		return true // Default to enabled for security
	}
	return *b.HTTP.MITM
}

// Load reads abox.yaml from the specified directory (or current directory if empty).
// Returns the parsed Boxfile and the directory containing the file.
func Load(dir string) (*Boxfile, string, error) {
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	// Convert to absolute path
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve path: %w", err)
	}

	boxfilePath := filepath.Join(absDir, "abox.yaml")

	data, err := os.ReadFile(boxfilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("abox.yaml not found in %s", absDir)
		}
		return nil, "", fmt.Errorf("failed to read abox.yaml: %w", err)
	}

	// Check if version field exists in the raw YAML (required field)
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, "", fmt.Errorf("failed to parse abox.yaml: %w", err)
	}
	rawVersion, hasVersion := raw["version"]
	if !hasVersion {
		return nil, "", config.CheckVersion(0, CurrentBoxfileVersion, "abox.yaml")
	}

	// Start with defaults
	box := DefaultBoxfile()

	if err := yaml.Unmarshal(data, box); err != nil {
		return nil, "", fmt.Errorf("failed to parse abox.yaml: %w", err)
	}

	// Validate config version (check for future versions)
	version, _ := rawVersion.(int)
	if err := config.CheckVersion(version, CurrentBoxfileVersion, "abox.yaml"); err != nil {
		return nil, "", err
	}

	return box, absDir, nil
}

// Validate checks that required fields are present and paths exist.
func (b *Boxfile) Validate(baseDir string) error {
	if err := b.validateNameAndUser(); err != nil {
		return err
	}
	if err := b.validateResources(); err != nil {
		return err
	}
	if err := b.validateProvisionScripts(baseDir); err != nil {
		return err
	}
	if err := b.validateOverlay(baseDir); err != nil {
		return err
	}
	if err := b.validateMonitor(baseDir); err != nil {
		return err
	}
	if err := b.validateOverrides(baseDir); err != nil {
		return err
	}
	return b.validateDNS()
}

func (b *Boxfile) validateNameAndUser() error {
	if b.Name == "" {
		return errors.New("name is required in abox.yaml")
	}
	if err := validation.ValidateInstanceName(b.Name); err != nil {
		return fmt.Errorf("invalid name in abox.yaml: %w", err)
	}
	if b.User != "" {
		if err := validation.ValidateSSHUser(b.User); err != nil {
			return fmt.Errorf("invalid user in abox.yaml: %w", err)
		}
	}
	return nil
}

func (b *Boxfile) validateResources() error {
	if err := validation.ValidateResourceLimits(b.CPUs, b.Memory); err != nil {
		return fmt.Errorf("invalid resource limits in abox.yaml: %w", err)
	}
	if b.Disk != "" {
		if err := validation.ValidateDiskSize(b.Disk); err != nil {
			return fmt.Errorf("invalid disk size in abox.yaml: %w", err)
		}
	}
	return nil
}

func (b *Boxfile) validateProvisionScripts(baseDir string) error {
	for _, script := range b.Provision {
		scriptPath, err := resolvePath(baseDir, script)
		if err != nil {
			return fmt.Errorf("provision script %q: %w", script, err)
		}
		if _, err := os.Stat(scriptPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("provision script not found: %s", scriptPath)
			}
			return fmt.Errorf("provision script %q: %w", script, err)
		}
	}
	return nil
}

func (b *Boxfile) validateOverlay(baseDir string) error {
	if b.Overlay == "" {
		return nil
	}
	overlayPath, err := resolvePath(baseDir, b.Overlay)
	if err != nil {
		return fmt.Errorf("overlay %q: %w", b.Overlay, err)
	}
	info, err := os.Stat(overlayPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("overlay directory not found: %s", overlayPath)
		}
		return fmt.Errorf("overlay %q: %w", b.Overlay, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("overlay path is not a directory: %s", overlayPath)
	}
	return nil
}

func (b *Boxfile) validateMonitor(baseDir string) error {
	if len(b.Monitor.Kprobes) > 0 && len(b.Monitor.Policies) > 0 {
		return errors.New("monitor.kprobes and monitor.policies are mutually exclusive in abox.yaml")
	}
	for _, name := range b.Monitor.Kprobes {
		if !policy.ValidKprobe(name) {
			return fmt.Errorf("unknown monitor kprobe %q in abox.yaml; valid kprobes: %v", name, policy.AllKprobeNames())
		}
	}
	for _, p := range b.Monitor.Policies {
		policyPath, err := resolvePath(baseDir, p)
		if err != nil {
			return fmt.Errorf("monitor policy %q: %w", p, err)
		}
		if _, err := os.Stat(policyPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("monitor policy file not found: %s", policyPath)
			}
			return fmt.Errorf("monitor policy %q: %w", p, err)
		}
	}
	return nil
}

// validateOverrides checks that override file paths exist and are readable.
// Content validation (e.g., template syntax) is deferred to the backend layer
// which has the knowledge to validate its own override formats.
func (b *Boxfile) validateOverrides(baseDir string) error {
	for backend, overrides := range b.Overrides {
		for key, path := range overrides {
			if path == "" {
				continue
			}
			qualifiedKey := backend + "." + key
			resolved, err := resolvePath(baseDir, path)
			if err != nil {
				return fmt.Errorf("overrides.%s %q: %w", qualifiedKey, path, err)
			}
			if _, err := os.Stat(resolved); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("overrides.%s not found: %s", qualifiedKey, resolved)
				}
				return fmt.Errorf("overrides.%s: %w", qualifiedKey, err)
			}
		}
	}
	return nil
}

func (b *Boxfile) validateDNS() error {
	if b.DNS.Upstream != "" {
		normalized, err := validation.NormalizeUpstreamDNS(b.DNS.Upstream)
		if err != nil {
			return fmt.Errorf("invalid dns.upstream in abox.yaml: %w", err)
		}
		b.DNS.Upstream = normalized
	}
	return nil
}

// resolvePath resolves a path relative to the base directory.
// Absolute paths are returned as-is. Relative paths are joined with baseDir
// and checked for path traversal (escaping baseDir).
func resolvePath(baseDir, path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	resolved := filepath.Clean(filepath.Join(baseDir, path))
	cleanBase := filepath.Clean(baseDir)
	if resolved != cleanBase && !strings.HasPrefix(resolved, cleanBase+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes base directory %q", path, baseDir)
	}
	return resolved, nil
}

// ResolveProvisionPaths returns absolute paths for all provision scripts.
func (b *Boxfile) ResolveProvisionPaths(baseDir string) ([]string, error) {
	paths := make([]string, len(b.Provision))
	for i, script := range b.Provision {
		p, err := resolvePath(baseDir, script)
		if err != nil {
			return nil, fmt.Errorf("provision script %q: %w", script, err)
		}
		paths[i] = p
	}
	return paths, nil
}

// ResolvePolicyPaths returns absolute paths for all monitor policy files.
func (b *Boxfile) ResolvePolicyPaths(baseDir string) ([]string, error) {
	paths := make([]string, len(b.Monitor.Policies))
	for i, p := range b.Monitor.Policies {
		resolved, err := resolvePath(baseDir, p)
		if err != nil {
			return nil, fmt.Errorf("monitor policy %q: %w", p, err)
		}
		paths[i] = resolved
	}
	return paths, nil
}

// ResolveOverridePath returns the absolute path for an override value.
// Returns empty string if the override is not configured.
func (b *Boxfile) ResolveOverridePath(backend, key, baseDir string) (string, error) {
	path := b.Overrides[backend][key]
	if path == "" {
		return "", nil
	}
	return resolvePath(baseDir, path)
}

// LoadOverrideContent reads an override file and returns its content.
// Returns empty string if the override is not configured.
func (b *Boxfile) LoadOverrideContent(backend, key, baseDir string) (string, error) {
	path := b.Overrides[backend][key]
	if path == "" {
		return "", nil
	}
	resolved, err := b.ResolveOverridePath(backend, key, baseDir)
	if err != nil {
		return "", err
	}
	content, err := os.ReadFile(resolved)
	if err != nil {
		return "", fmt.Errorf("failed to read override %s.%s: %w", backend, key, err)
	}
	return string(content), nil
}

// ResolveOverlayPath returns the absolute path for the overlay directory.
func (b *Boxfile) ResolveOverlayPath(baseDir string) (string, error) {
	if b.Overlay == "" {
		return "", nil
	}
	return resolvePath(baseDir, b.Overlay)
}
