package config

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// GlobalConfig holds global abox configuration.
type GlobalConfig struct {
	Version    int    `yaml:"version"`
	SubnetPool string `yaml:"subnet_pool"` // Default: "10.10.0.0/16"
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

	return cfg, nil
}
