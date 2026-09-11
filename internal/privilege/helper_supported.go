//go:build linux || darwin

package privilege

// Shared helper-server pieces used only by the platforms that actually run a
// privileged helper (Egress/iptables on Linux, Pf/pfctl on darwin). They live in
// this linux||darwin file rather than the untagged helper.go so they are not
// compiled — and thus not flagged unused — on platforms where the helper refuses
// to start (see helper_other.go).

import (
	"time"

	"github.com/sandialabs/abox/internal/rpc"
)

// pingResponse is the body of the Ping RPC response.
const pingResponse = "pong"

// safeEnv is the minimal environment for child processes.
// Defense-in-depth: even though the setuid binary clears its own environment
// at startup, explicitly setting cmd.Env prevents any env vars set by Go
// runtime or library code from leaking to iptables.
var safeEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// pingReply builds the health-check response body shared by every platform's
// helper server (EgressServer on Linux, PfServer on darwin).
func pingReply() *rpc.StringMsg {
	return &rpc.StringMsg{Message: pingResponse}
}

// shutdownServerAsync performs the shared graceful-shutdown dance used by every
// platform's helper Shutdown RPC: after a brief delay (so the RPC response is
// sent first) it GracefulStops the stored gRPC server, which causes
// server.Serve() in RunHelper to return and its deferred socket cleanup to run.
func shutdownServerAsync() {
	go func() {
		// Brief delay to allow the RPC response to be sent.
		time.Sleep(50 * time.Millisecond)

		shutdownState.mu.Lock()
		srv := shutdownState.server
		shutdownState.mu.Unlock()

		// Gracefully stop the gRPC server (drains in-flight RPCs). This causes
		// server.Serve() in RunHelper to return, allowing deferred cleanup to run.
		if srv != nil {
			srv.GracefulStop()
		}
	}()
}
