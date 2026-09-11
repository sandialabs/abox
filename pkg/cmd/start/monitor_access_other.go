//go:build !linux

package start

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
)

// warnIfMonitorSocketInaccessible is a no-op off Linux: the libvirt/qemu
// socket-group model does not apply to the vfkit backend, and monitoring is
// rejected up front on backends without a monitor transport.
func warnIfMonitorSocketInaccessible(_ io.Writer, _ *config.Paths) {}
