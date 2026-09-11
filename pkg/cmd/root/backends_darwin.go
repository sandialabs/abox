//go:build darwin

package root

// Register the VM backend on macOS via blank import; the backend self-registers
// in its init() function. The VMware (vmrun / Fusion) backend package now
// compiles on darwin and is registered here, but it is EXPERIMENTAL and unproven
// on macOS: it has had no real-host validation (no live Fusion/vmnet run).
// Registering it makes the code path available for development, not a supported
// configuration; auto-detection never selects it — reaching it requires an
// explicit ABOX_BACKEND=vmware. (The OS seams it shares with vfkit — advisory
// file locking in internal/images and process-group detach in internal/procutil
// — are real on darwin, which satisfies //go:build unix; only the !unix/Windows
// stubs are no-ops.)
import (
	// vfkit is the macOS VM backend (Apple Virtualization.framework); it
	// self-registers as the darwin auto-detect default in its init().
	_ "github.com/sandialabs/abox/internal/backend/vfkit"
	_ "github.com/sandialabs/abox/internal/backend/vmware"
)
