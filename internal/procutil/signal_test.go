package procutil

import (
	"os"
	"testing"
)

// TestIsAliveCurrentProcess verifies the liveness probe recognizes the running
// test process and rejects non-positive PIDs. This holds on every platform (the
// unix impl uses signal 0; the stub uses os.FindProcess).
func TestIsAliveCurrentProcess(t *testing.T) {
	if !IsAlive(os.Getpid()) {
		t.Fatal("expected the current process to be reported alive")
	}
	if IsAlive(0) {
		t.Fatal("expected pid 0 to be reported not alive")
	}
	if IsAlive(-1) {
		t.Fatal("expected a negative pid to be reported not alive")
	}
}
