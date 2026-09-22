//go:build darwin

package vmrun

// hostTypeDefault is the vmrun "-T" host driver on macOS: VMware Fusion.
func hostTypeDefault() string { return "fusion" }
