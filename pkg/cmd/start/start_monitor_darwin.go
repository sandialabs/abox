//go:build darwin

package start

import (
	"errors"

	"github.com/sandialabs/abox/internal/config"
)

// guardMonitor refuses to start an instance with monitor.enabled on macOS.
// Tetragon is eBPF-based and requires a Linux host; on darwin the virtio-serial
// path vfkit provides is not wired the same way libvirt's is, and the monitor
// daemon would wait forever for events that never arrive.
func guardMonitor(inst *config.Instance) error {
	if inst != nil && inst.Monitor.Enabled {
		return errors.New("monitor is not supported on macOS (Tetragon requires a Linux host with eBPF support); set monitor.enabled: false in abox.yaml")
	}
	return nil
}
