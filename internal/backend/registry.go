package backend

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
)

// registry holds registered backends and provides selection logic.
var registry = &backendRegistry{
	backends: make(map[string]Factory),
}

// OverrideEntry holds a registered override default.
type OverrideEntry struct {
	// Fn returns the built-in default content for this override key.
	Fn func() string
	// Description is a human-readable description shown in help text.
	Description string
}

// overrideDefaults maps override keys (e.g., "libvirt.template") to their entries.
// Populated by backend init() functions.
var overrideDefaults = make(map[string]OverrideEntry)

// RegisterOverrideDefault registers a built-in default for an override key.
// description is shown in help text (e.g., "Libvirt domain XML template for defining VMs").
// This should be called from init() in each backend package.
func RegisterOverrideDefault(key string, fn func() string, description string) {
	overrideDefaults[key] = OverrideEntry{Fn: fn, Description: description}
}

// OverrideDefaults returns a copy of all registered override entries.
func OverrideDefaults() map[string]OverrideEntry {
	result := make(map[string]OverrideEntry, len(overrideDefaults))
	maps.Copy(result, overrideDefaults)
	return result
}

// Factory creates a new Backend instance.
type Factory func() Backend

// backendRegistry manages registered backends.
type backendRegistry struct {
	mu       sync.RWMutex
	backends map[string]Factory
	// priority determines the order in which backends are tried during auto-detection.
	// Lower numbers are tried first.
	priority map[string]int
}

// Register registers a backend factory with the given name and priority.
// Lower priority values are tried first during auto-detection.
// This should be called from init() in each backend package.
func Register(name string, priority int, factory Factory) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	registry.backends[name] = factory
	if registry.priority == nil {
		registry.priority = make(map[string]int)
	}
	registry.priority[name] = priority
}

// AutoDetect finds the first available backend on the current system.
// Backends are tried in priority order (lowest first).
func AutoDetect() (Backend, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	if len(registry.backends) == 0 {
		return nil, ErrNoBackendAvailable
	}

	// Sort backends by priority
	names := make([]string, 0, len(registry.backends))
	for name := range registry.backends {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return registry.priority[names[i]] < registry.priority[names[j]]
	})

	// Try each backend in priority order
	var errs []string
	for _, name := range names {
		factory := registry.backends[name]
		b := factory()
		err := b.IsAvailable()
		if err == nil {
			return b, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", name, err))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoBackendAvailable, strings.Join(errs, "; "))
	}
	return nil, ErrNoBackendAvailable
}

// Get returns a specific backend by name.
// Returns ErrBackendNotFound if the backend is not registered.
// Returns the availability error if the backend is registered but not available.
func Get(name string) (Backend, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	factory, ok := registry.backends[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, name)
	}

	b := factory()
	if err := b.IsAvailable(); err != nil {
		return nil, fmt.Errorf("backend %s is not available: %w", name, err)
	}

	return b, nil
}

// ForInstance returns the appropriate backend for an instance.
// If the instance has a backend specified in its config, that backend is used.
// Otherwise, auto-detection is performed.
func ForInstance(inst interface{ GetBackend() string }) (Backend, error) {
	backendName := inst.GetBackend()
	if backendName == "" {
		return AutoDetect()
	}
	return Get(backendName)
}

// ResetForTesting clears all registered backends and override defaults. Only for use in tests.
func ResetForTesting() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.backends = make(map[string]Factory)
	registry.priority = make(map[string]int)
	overrideDefaults = make(map[string]OverrideEntry)
}
