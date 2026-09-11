//go:build linux

package main

// Register the VM backends available on Linux via blank import; each backend
// self-registers in its init(). Mirrors pkg/cmd/root/backends_linux.go so the
// matrix's registry matches the abox binary it drives.
import (
	_ "github.com/sandialabs/abox/internal/backend/libvirt"
	_ "github.com/sandialabs/abox/internal/backend/vmware"
)
