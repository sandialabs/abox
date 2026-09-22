package config

// BackendConfig keys. BackendConfig is a free-form map[string]any populated from
// YAML/JSON and owned collectively by the VM backends. Centralizing the key names
// here keeps readers and writers in agreement and gives the typed accessors below
// a single source of truth.
//
// Note: the VMware host-only network key ("vnet") is defined as
// vmrun.VNetConfigKey and reused as-is (config must not import vmrun, which would
// be an import cycle); callers pass that constant to the accessors below.
const (
	// BackendKeyUUID stores the VM UUID (string). Used by the vfkit backend.
	BackendKeyUUID = "uuid"
	// BackendKeyRESTPort stores the vfkit REST API port (numeric). It may
	// round-trip through JSON as a float64 or through YAML as an int; use
	// BackendInt to read it robustly.
	BackendKeyRESTPort = "rest_port"
	// BackendKeyBridge stores the resolved host bridge interface recorded once
	// the VM is up (string). Used by the vfkit backend and the tap command.
	BackendKeyBridge = "bridge"
	// BackendKeyCustomTemplate records whether a custom domain template is stored
	// for the instance (bool). Used by the libvirt backend.
	BackendKeyCustomTemplate = "custom_template"
	// BackendKeyFirmware selects the VMware .vmx firmware ("efi" to override the
	// default BIOS; string). Used by the vmrun .vmx generator.
	BackendKeyFirmware = "firmware"
)

// BackendString returns the string stored under key in BackendConfig. The second
// return is true only when the key is present and holds a string value; it is
// nil-safe (a nil BackendConfig yields "", false). Callers that treat an empty
// value as "unset" should additionally check the returned string.
func (i *Instance) BackendString(key string) (string, bool) {
	if i == nil || i.BackendConfig == nil {
		return "", false
	}
	v, ok := i.BackendConfig[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

// BackendInt returns the integer stored under key in BackendConfig. The second
// return is true only when the key is present and holds a numeric value.
//
// A single logical value may arrive as different concrete types depending on how
// the config was decoded: YAML decodes plain integers to int, while a JSON
// round-trip turns every number into float64. To read such values consistently
// this accepts int, int64, float64 and float32; floating-point values are
// truncated toward zero. It is nil-safe (a nil BackendConfig yields 0, false).
func (i *Instance) BackendInt(key string) (int, bool) {
	if i == nil || i.BackendConfig == nil {
		return 0, false
	}
	v, ok := i.BackendConfig[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	default:
		return 0, false
	}
}

// BackendBool returns the boolean stored under key in BackendConfig. The second
// return is true only when the key is present and holds a bool value; it is
// nil-safe (a nil BackendConfig yields false, false).
func (i *Instance) BackendBool(key string) (bool, bool) {
	if i == nil || i.BackendConfig == nil {
		return false, false
	}
	v, ok := i.BackendConfig[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	if !ok {
		return false, false
	}
	return b, true
}
