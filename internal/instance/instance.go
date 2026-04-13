// Package instance provides helper functions for loading and validating instances.
package instance

import (
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

// LoadRequired checks that an instance exists and loads its configuration.
// Returns an error if the instance does not exist.
func LoadRequired(name string) (*config.Instance, *config.Paths, error) {
	if !config.Exists(name) {
		return nil, nil, fmt.Errorf("instance %q does not exist", name)
	}

	inst, paths, err := config.Load(name)
	if err != nil {
		return nil, nil, err
	}

	return inst, paths, nil
}

// LoadRunning loads an instance's configuration and verifies the VM is running.
// The vm parameter is used to check if the VM is running via the backend interface.
// Returns an error if the instance does not exist or is not running.
func LoadRunning(name string, vm backend.VMManager) (*config.Instance, *config.Paths, error) {
	inst, paths, err := LoadRequired(name)
	if err != nil {
		return nil, nil, err
	}

	if !vm.IsRunning(name) {
		return nil, nil, fmt.Errorf("instance %q is not running", name)
	}

	return inst, paths, nil
}

// GetIP returns the IP address for an instance, with fallback to the configured address.
// The vm parameter is used to query the VM's IP via the backend interface.
// Returns an error if no IP address can be determined.
func GetIP(inst *config.Instance, vm backend.VMManager) (string, error) {
	ip, err := vm.GetIP(inst.Name)
	if err != nil {
		// Fall back to configured IP
		ip = inst.IPAddress
	}

	if ip == "" {
		return "", fmt.Errorf("could not determine IP address for instance %q", inst.Name)
	}

	return ip, nil
}
