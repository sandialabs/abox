package config

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"github.com/sandialabs/abox/internal/validation"
)

// GlobalConfig holds global abox configuration.
type GlobalConfig struct {
	Version    int    `yaml:"version"`
	SubnetPool string `yaml:"subnet_pool"` // Default: "10.10.0.0/16"
	// StorageDir overrides the backend's default root for disk images (e.g.
	// /scratch/<user>/abox); see GetPathsForNewInstance. It must be a directory
	// the calling user owns; on libvirt the privilege helper group-shares it with
	// the QEMU process (see EnsureStorageRoot). Only affects newly created
	// instances: existing ones keep the storage_dir persisted in their own config.
	StorageDir string `yaml:"storage_dir,omitempty"`
}

// DefaultGlobalConfig returns a GlobalConfig with default values.
func DefaultGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		Version:    CurrentGlobalVersion,
		SubnetPool: "10.10.0.0/16",
	}
}

// GetGlobalConfigPath returns the path to the global config file.
// Respects XDG_CONFIG_HOME.
func GetGlobalConfigPath() string {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "abox", "config.yaml")
}

// LoadGlobalConfig loads the global configuration from disk.
// Returns default config if file doesn't exist.
func LoadGlobalConfig() (*GlobalConfig, error) {
	path := GetGlobalConfigPath()
	if path == "" {
		return DefaultGlobalConfig(), nil
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return DefaultGlobalConfig(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read global config: %w", err)
	}

	// Check if version field exists in the raw YAML (required field)
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse global config: %w", err)
	}
	rawVersion, hasVersion := raw["version"]
	if !hasVersion {
		return nil, CheckVersion(0, CurrentGlobalVersion, "global config")
	}

	cfg := DefaultGlobalConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse global config: %w", err)
	}

	// Validate config version (check for future versions)
	version, ok := rawVersion.(int)
	if !ok {
		return nil, fmt.Errorf("global config: version field must be an integer, got %T", rawVersion)
	}
	if err := CheckVersion(version, CurrentGlobalVersion, "global config"); err != nil {
		return nil, err
	}
	if _, err := parseSubnetPool(cfg.SubnetPool); err != nil {
		return nil, fmt.Errorf("global config: subnet_pool: %w", err)
	}
	if cfg.StorageDir != "" {
		if err := validateStorageDir(cfg.StorageDir); err != nil {
			return nil, fmt.Errorf("global config: %w", err)
		}
		cfg.StorageDir = filepath.Clean(cfg.StorageDir)
		// The caller's own default root is allowed (it's what an unset
		// storage_dir means); anything else in the shared tree is not.
		if cfg.StorageDir != LibvirtStorageDir() {
			if err := validation.ValidateStorageRoot(cfg.StorageDir, LibvirtImagesDir); err != nil {
				return nil, fmt.Errorf("global config: storage_dir: %w", err)
			}
		}
	}

	return cfg, nil
}

// GetPathsForNewInstance resolves paths for an instance being created or
// imported: under the user-configured storage_dir if set, else under
// backendStorageDir (the backend's default, be.StorageDir()). The chosen root is
// returned as Paths.StorageDir, which callers persist as the instance's
// storage_dir so later commands never consult the global config again. A
// global config that fails to load or validate is an error, not a fallback:
// silently using the default would put disks somewhere the user didn't ask for.
func GetPathsForNewInstance(name, backendStorageDir string) (*Paths, error) {
	cfg, err := LoadGlobalConfig()
	if err != nil {
		return nil, err
	}
	storageDir := backendStorageDir
	if cfg.StorageDir != "" {
		storageDir = cfg.StorageDir
	}
	return GetPathsWithStorage(name, storageDir)
}
