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
	// experimental marks backends that must not be chosen by silent auto-detection;
	// they are reachable only by explicit selection (see AutoDetect / IsExperimental).
	experimental map[string]bool
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

// RegisterExperimental registers a backend like Register but marks it
// experimental: AutoDetect will never select it silently, so it is reachable only
// by explicit selection (e.g. ABOX_BACKEND). Use for backends that compile and
// unit-test but have not been validated end-to-end on real hardware.
func RegisterExperimental(name string, priority int, factory Factory) {
	Register(name, priority, factory)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.experimental == nil {
		registry.experimental = make(map[string]bool)
	}
	registry.experimental[name] = true
}

// IsExperimental reports whether the named backend was registered as experimental.
func IsExperimental(name string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.experimental[name]
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
		if pi, pj := registry.priority[names[i]], registry.priority[names[j]]; pi != pj {
			return pi < pj
		}
		return names[i] < names[j] // deterministic tiebreak for equal priorities
	})

	// Try each backend in priority order. Experimental backends are never chosen
	// silently — they require explicit selection — but we track any that WOULD have
	// been available so the error can point the user at them.
	var errs []string
	var experimentalErrs []string
	var availableExperimental []string
	for _, name := range names {
		factory := registry.backends[name]
		b := factory()
		err := b.IsAvailable()
		if registry.experimental[name] {
			if err == nil {
				availableExperimental = append(availableExperimental, name)
			} else {
				// Keep experimental failures separate from the stable errs (which
				// feed the "stable backends unavailable" message) so they can be
				// appended as supplementary diagnostics, letting an all-experimental
				// host (e.g. vmware on Windows) — or a host where both the stable and
				// experimental backends failed — get a diagnosable reason.
				experimentalErrs = append(experimentalErrs, fmt.Sprintf("%s: %v", name, err))
			}
			continue
		}
		if err == nil {
			return b, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", name, err))
	}

	if len(availableExperimental) > 0 {
		msg := fmt.Sprintf("no stable backend detected; the experimental backend(s) %s are available but must be selected explicitly (set ABOX_BACKEND=<name>)",
			strings.Join(availableExperimental, ", "))
		// Preserve the concrete stable-backend failure reasons so the user can still
		// diagnose why the stable backend was rejected.
		if len(errs) > 0 {
			msg += "; stable backends unavailable: " + strings.Join(errs, "; ")
		}
		return nil, fmt.Errorf("%w: %s", ErrNoBackendAvailable, msg)
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		// Also surface why any experimental backend was rejected, so a host where
		// both a stable and an experimental backend failed does not lose the
		// experimental diagnostics.
		if len(experimentalErrs) > 0 {
			msg += "; experimental backends also unavailable: " + strings.Join(experimentalErrs, "; ")
		}
		return nil, fmt.Errorf("%w: %s", ErrNoBackendAvailable, msg)
	}
	if len(experimentalErrs) > 0 {
		return nil, fmt.Errorf("%w: the only registered backend(s) are experimental and unavailable: %s (select one explicitly with ABOX_BACKEND=<name> once its requirements are met)",
			ErrNoBackendAvailable, strings.Join(experimentalErrs, "; "))
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

// RequiredToolsByBackend returns the tools each registered backend declares via
// ToolRequirer, keyed by backend name. Backends that do not implement
// ToolRequirer are omitted. Unlike Get, it does NOT check availability — it
// constructs each backend only to read its static tool list.
func RequiredToolsByBackend() map[string][]Tool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	result := make(map[string][]Tool)
	for name, factory := range registry.backends {
		if tr, ok := factory().(ToolRequirer); ok {
			result[name] = tr.RequiredTools()
		}
	}
	return result
}

// RegisteredNames returns the names of all registered backends, ordered by
// priority (tried-first / lowest priority first), mirroring AutoDetect and
// DefaultName. It performs NO availability check.
func RegisteredNames() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	names := make([]string, 0, len(registry.backends))
	for name := range registry.backends {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if pi, pj := registry.priority[names[i]], registry.priority[names[j]]; pi != pj {
			return pi < pj
		}
		return names[i] < names[j] // deterministic tiebreak for equal priorities
	})
	return names
}

// IsRegistered reports whether a backend with the given name is registered.
func IsRegistered(name string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	_, ok := registry.backends[name]
	return ok
}

// DefaultName returns the name check-deps should treat as the primary backend:
// the lowest-priority (tried-first) non-experimental registered backend, else
// the lowest-priority registered backend, else "" when none are registered.
// It performs NO availability check.
func DefaultName() string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	if len(registry.backends) == 0 {
		return ""
	}

	// Sort backends by priority (lowest first), mirroring AutoDetect.
	names := make([]string, 0, len(registry.backends))
	for name := range registry.backends {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if pi, pj := registry.priority[names[i]], registry.priority[names[j]]; pi != pj {
			return pi < pj
		}
		return names[i] < names[j] // deterministic tiebreak for equal priorities
	})

	// Prefer the first non-experimental backend; fall back to the first overall.
	for _, name := range names {
		if !registry.experimental[name] {
			return name
		}
	}
	return names[0]
}

// ResetForTesting clears all registered backends and override defaults. Only for use in tests.
func ResetForTesting() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.backends = make(map[string]Factory)
	registry.priority = make(map[string]int)
	registry.experimental = make(map[string]bool)
	overrideDefaults = make(map[string]OverrideEntry)
}
