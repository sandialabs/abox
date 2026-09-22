//go:build linux

package start

import (
	"fmt"
	"io"
	"time"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/monitor"
	"github.com/sandialabs/abox/internal/privilege"
)

// warnIfMonitorSocketInaccessible warns when the libvirt-created virtio-serial
// monitor socket is owned by a qemu group the caller is not a member of — in
// which case the monitor daemon connects to nothing and silently captures zero
// events. It briefly waits for libvirt to create the socket after VM start, then
// prints an actionable `usermod -aG` hint. Linux/libvirt-specific (the socket
// group model does not apply to the vfkit backend); a no-op elsewhere.
func warnIfMonitorSocketInaccessible(w io.Writer, paths *config.Paths) {
	deadline := time.Now().Add(5 * time.Second)
	for !monitor.IsAvailable(paths.MonitorSocket) {
		if time.Now().After(deadline) {
			return // never appeared; the daemon's own retry/logging covers this
		}
		time.Sleep(200 * time.Millisecond)
	}

	access, err := privilege.CheckSocketGroupAccess(paths.MonitorSocket)
	if err != nil || access.IsMember {
		return
	}

	fmt.Fprintln(w, "Warning: monitor events may not be captured.")
	fmt.Fprintf(w, "  The monitor socket is owned by group %q, which you are not a member of,\n", access.Group)
	fmt.Fprintln(w, "  so the monitor daemon cannot connect to it.")
	fmt.Fprintf(w, "  Fix: sudo usermod -aG %s \"$USER\"  (then start a new login session)\n", access.Group)
}
