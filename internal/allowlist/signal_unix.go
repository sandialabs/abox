//go:build unix

package allowlist

import (
	"os"
	"os/signal"
	"syscall"
)

// registerReloadSignal returns a channel that receives a value whenever the
// process is sent SIGHUP, the conventional "reload configuration" signal.
func registerReloadSignal() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}

// stopReloadSignal stops delivery of the reload signal to ch (no-op if nil).
func stopReloadSignal(ch chan os.Signal) {
	if ch != nil {
		signal.Stop(ch)
	}
}
