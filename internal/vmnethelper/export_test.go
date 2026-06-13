//go:build darwin

package vmnethelper

import "sync"

// resetSudoProbe flushes the cached sw_vers probe so tests can swap
// productVersionFn and re-invoke NeedsSudo.
func resetSudoProbe() {
	needsSudoOnce = sync.Once{}
	needsSudoVal = false
}
