//go:build windows

package root

// Register the VM backend on Windows via blank import; the backend self-registers
// in its init() function. The VMware (vmrun / Workstation) backend package now
// compiles on windows and is registered here, but it is EXPERIMENTAL and unproven
// on Windows: it has had no real-host validation (no live Workstation/vmnet run),
// and several OS seams it depends on are Linux-only no-ops off Linux (see the
// TODO(windows-backend) markers in internal/images/lock_other.go and
// internal/procutil/detach_other.go). Registering it makes the code path
// available for development, not a supported configuration.
import _ "github.com/sandialabs/abox/internal/backend/vmware"
