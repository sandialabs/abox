//go:build e2e && linux

package e2e

// Register the Linux VM backends so they self-register in the registry, matching
// production wiring (pkg/cmd/root/backends_linux.go). Without this the e2e
// harness could not resolve a backend by name for capability-based skips.
import (
	_ "github.com/sandialabs/abox/internal/backend/libvirt"
	_ "github.com/sandialabs/abox/internal/backend/vmware"
)
