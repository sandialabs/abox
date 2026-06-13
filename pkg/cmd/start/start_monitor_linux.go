//go:build linux

package start

import "github.com/sandialabs/abox/internal/config"

// guardMonitor is a no-op on Linux: Tetragon/eBPF monitoring is supported.
func guardMonitor(_ *config.Instance) error { return nil }
