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
	ln, err := unixListen(path)
	if err != nil {
		t.Fatalf("unixListen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("socket not created: %v", err)
	}
}

func TestUnixListenSecureRemovesStale(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	// A leftover file at the socket path with nothing listening on it (as after a
	// crash). The bind fails, the dial fails, so it must be removed and retried.
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := UnixListenSecure(path)
	if err != nil {
		t.Fatalf("UnixListenSecure should reclaim a stale socket: %v", err)
	}
	defer func() { _ = ln.Close() }()
}

func TestUnixListenSecureRejectsLive(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	live, err := unixListen(path)
	if err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	defer func() { _ = live.Close() }()

	// Something is actively listening — the socket is in use, not stale.
	ln, err := UnixListenSecure(path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("UnixListenSecure must refuse a socket in active use")
	}
}

func TestUnixListenSecureAcceptsSameUID(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := UnixListenSecure(path)
	if err != nil {
		t.Fatalf("UnixListenSecure: %v", err)
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
	// Wrap the raw listener directly so we can inject a non-matching UID;
	// UnixListenSecure pins the allowed UID to os.Getuid() by design.
	base, err := unixListenWithStaleCheck(path)
	if err != nil {
		t.Fatalf("unixListenWithStaleCheck: %v", err)
	}
	ln := &uidCheckListener{Listener: base, allowedUID: os.Getuid() + 1}

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

// TestUnixListenWithUIDCheckSetsModeAndOwner verifies the fd-based
// applySocketPermissions path: the created socket ends up with the expected
// peer-check mode and is owned by the allowed UID. Uses the current UID as the
// allowed UID so the chown-to-self succeeds without root. The Fstat verification
// inside applySocketPermissions would fail the listen if the fd-based chmod/chown
// silently no-op'd, so a passing listen also asserts the change took effect.
func TestUnixListenWithUIDCheckSetsModeAndOwner(t *testing.T) {
	requireUnixSocket(t)
	path := filepath.Join(t.TempDir(), "helper.sock")
	ln, err := UnixListenWithUIDCheck(path, os.Getuid())
	if err != nil {
		t.Fatalf("UnixListenWithUIDCheck: %v", err)
	}
	defer func() { _ = ln.Close() }()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if fi.Mode().Perm() != socketPeerCheckMode.Perm() {
		t.Errorf("socket mode = %o, want %o", fi.Mode().Perm(), socketPeerCheckMode.Perm())
	}
}

// TestApplySocketPermissions_RejectsPlantedSymlink is the regression guard:
// if the just-bound socket is swapped for a symlink to a victim file before
// applySocketPermissions runs, the chmod/chown must NOT follow the symlink (which
// would chmod the victim). The pinned-inode approach must reject the non-socket.
func TestApplySocketPermissions_RejectsPlantedSymlink(t *testing.T) {
	requireUnixSocket(t)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "helper.sock")

	ln, err := unixListen(path)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Attacker swaps the socket for a symlink to a root-ish victim file.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path)
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}

	// applySocketPermissions must refuse (target is now a symlink, not a socket)
	// and must NOT have changed the victim's mode.
	if err := applySocketPermissions(ln, path, socketPeerCheckMode, os.Getuid()); err == nil {
		t.Fatal("applySocketPermissions must reject a symlink planted at the socket path")
	}
	fi, err := os.Lstat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("victim mode changed to %o; the chmod followed the planted symlink", fi.Mode().Perm())
	}
}
