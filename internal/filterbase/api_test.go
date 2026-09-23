package filterbase

import (
	"net"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/allowlist"
)

// TestBaseAPIServer_StartUsesSecureListener verifies that the filter API
// server listens via the secure (peer-UID-checking) listener and accepts a
// same-user connection. Cross-UID rejection itself is covered by the rpc package
// tests; here we only confirm the server wires up the secure listener and works
// for the legitimate same-user case.
func TestBaseAPIServer_StartUsesSecureListener(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "api.sock")
	// Probe: skip on sandboxes that forbid AF_UNIX.
	if ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "probe.sock")); err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	} else {
		_ = ln.Close()
	}

	srv := NewBaseAPIServer(sock, allowlist.NewFilter(), nil, nil, "inst", "dns")
	if err := srv.Start(func(*grpc.Server) {}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Same-user dial is accepted by the secure listener.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("same-user dial should succeed: %v", err)
	}
	conn.Close()
}
