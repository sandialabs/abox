//go:build darwin

package main

// Register the macOS VM backends via blank import so they self-register in the
// registry, matching production wiring (pkg/cmd/root/backends_darwin.go): vfkit
// is the production default, vmware is experimental. libvirt is Linux-only.
// Without vfkit here, the no-flag matrix default (backend.RegisteredNames) would
// exercise only the experimental vmware backend and skip vfkit base-image cleanup.
import (
	_ "github.com/sandialabs/abox/internal/backend/vfkit"
	_ "github.com/sandialabs/abox/internal/backend/vmware"
)
