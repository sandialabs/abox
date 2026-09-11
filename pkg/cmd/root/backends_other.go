//go:build !linux && !darwin && !windows

package root

// No VM backends are available on platforms other than Linux, macOS, and
// Windows. Linux has libvirt + vmware, and macOS/Windows have the vmware
// backend (see backends_{linux,darwin,windows}.go). With nothing registered
// here, backend.AutoDetect returns ErrNoBackendAvailable, so VM operations fail
// cleanly while non-VM subcommands still work.
