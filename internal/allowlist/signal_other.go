//go:build !unix

package allowlist

import "os"

// registerReloadSignal returns nil on platforms without a reload signal
// (Windows has no SIGHUP). A nil channel never fires in the watch select, so
// file-watch reloads still work; only the manual signal trigger is absent.
func registerReloadSignal() chan os.Signal {
	return nil
}

// stopReloadSignal is a no-op on platforms without a reload signal.
func stopReloadSignal(_ chan os.Signal) {}
