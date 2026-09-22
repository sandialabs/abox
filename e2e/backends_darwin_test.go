//go:build e2e && darwin

package e2e

// Register the macOS VM backends so they self-register in the registry, matching
// production wiring (pkg/cmd/root/backends_darwin.go). Without this the e2e
// harness could not resolve a backend by name for capability-based skips.
import (
	_ "github.com/sandialabs/abox/internal/backend/vfkit"
	_ "github.com/sandialabs/abox/internal/backend/vmware"
)
