//go:build !darwin

package vmrun

// hostTypeDefault is the vmrun "-T" host driver everywhere except macOS: VMware
// Workstation ("ws"), used on Linux and Windows.
func hostTypeDefault() string { return "ws" }
