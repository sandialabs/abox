//go:build unix

package rpc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// requireUnixSocket skips when the environment forbids creating AF_UNIX sockets
// (e.g. a restricted sandbox), keeping the suite hermetic there while still
// exercising the code on real hosts/CI.
func requireUnixSocket(t *testing.T) {
	t.Helper()
	probe := filepath.Join(t.TempDir(), "probe.sock")
	ln, err := net.Listen("unix", probe)
	if err != nil {
		t.Skipf("unix sockets unavailable in this environment: %v", err)
	}
	_ = ln.Close()
}

func TestUnixListenFresh(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := UnixListen(path)
	if err != nil {
		t.Fatalf("UnixListen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("socket not created: %v", err)
	}
}

func TestUnixListenWithStaleCheckRemovesStale(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	// A leftover file at the socket path with nothing listening on it (as after a
	// crash). The bind fails, the dial fails, so it must be removed and retried.
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := UnixListenWithStaleCheck(path)
	if err != nil {
		t.Fatalf("UnixListenWithStaleCheck should reclaim a stale socket: %v", err)
	}
	defer func() { _ = ln.Close() }()
}

func TestUnixListenWithStaleCheckRejectsLive(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	live, err := UnixListen(path)
	if err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	defer func() { _ = live.Close() }()

	// Something is actively listening — the socket is in use, not stale.
	ln, err := UnixListenWithStaleCheck(path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("UnixListenWithStaleCheck must refuse a socket in active use")
	}
}

func TestUnixListenWithStaleAndUIDCheckAcceptsSameUID(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := UnixListenWithStaleAndUIDCheck(path, os.Getuid())
	if err != nil {
		t.Fatalf("UnixListenWithStaleAndUIDCheck: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if _, ok := ln.(*uidCheckListener); !ok {
		t.Fatalf("listener type = %T, want *uidCheckListener", ln)
	}

	go func() {
		c, derr := net.Dial("unix", path)
		if derr == nil {
			c.Close()
		}
	}()

	// The peer is this same process, so its UID matches the allowed UID and the
	// connection is accepted.
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept from same-UID peer: %v", err)
	}
	conn.Close()
}

// TestUIDCheckListenerDropsRejectedPeer verifies that a rejected/unverifiable
// peer does not make Accept return an error (which grpc.Serve would treat as
// fatal and shut the whole helper down). Accept must drop the bad connection
// and keep looping; only a genuine listener error (e.g. Close) terminates it.
func TestUIDCheckListenerDropsRejectedPeer(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	// allowedUID deliberately does not match this process, so every connection
	// this test dials is rejected (on platforms without SO_PEERCRED the peer
	// credentials lookup fails, which is likewise a drop-and-continue path).
	ln, err := UnixListenWithStaleAndUIDCheck(path, os.Getuid()+1)
	if err != nil {
		t.Fatalf("UnixListenWithStaleAndUIDCheck: %v", err)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, aerr := ln.Accept()
		done <- result{c, aerr}
	}()

	// Dial a connection that will be rejected. Accept must swallow it.
	if c, derr := net.Dial("unix", path); derr == nil {
		c.Close()
	}

	select {
	case r := <-done:
		if r.conn != nil {
			r.conn.Close()
		}
		t.Fatalf("Accept returned for a rejected peer (conn=%v, err=%v); it must drop and keep looping", r.conn, r.err)
	case <-time.After(300 * time.Millisecond):
		// Good: Accept is still looping, having dropped the rejected connection.
	}

	// A genuine listener error (Close) must still propagate out of Accept.
	_ = ln.Close()
	select {
	case r := <-done:
		if r.err == nil {
			if r.conn != nil {
				r.conn.Close()
			}
			t.Fatal("Accept must return an error once the underlying listener is closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after the listener was closed")
	}
}
