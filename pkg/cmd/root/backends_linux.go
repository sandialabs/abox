//go:build linux

package root

// Register VM backends available on Linux via blank import; each backend
// self-registers in its init() function. libvirt is the auto-detect default
// (lower priority); vmware (VMware Workstation) is also available on Linux and
// is chosen only when selected explicitly or as the sole available backend.
import (
	_ "github.com/sandialabs/abox/internal/backend/libvirt"
	_ "github.com/sandialabs/abox/internal/backend/vmware"
)
