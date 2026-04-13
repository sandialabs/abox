package config

import "fmt"

const (
	// CurrentInstanceVersion is the current version of the instance config format.
	CurrentInstanceVersion = 1

	// CurrentGlobalVersion is the current version of the global config format.
	CurrentGlobalVersion = 1
)

// CheckVersion validates a config version against the current supported version.
// Returns an error if version is missing (0) or newer than supported.
func CheckVersion(version, current int, configType string) error {
	if version == 0 {
		return fmt.Errorf("%s missing required 'version' field", configType)
	}
	if version > current {
		return fmt.Errorf("%s version %d is newer than supported (%d); please upgrade abox",
			configType, version, current)
	}
	return nil
}
