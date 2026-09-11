//go:build linux

package rpc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestGetPeerCredentialsSameUID verifies the Linux SO_PEERCRED path accepts a
// same-process (same-UID) peer and reports this process's uid and a positive pid.
// It uses a real local AF_UNIX socket pair; no privilege or external process is
// involved. Skips when the sandbox forbids AF_UNIX sockets (see requireUnixSocket).
func TestGetPeerCredentialsSameUID(t *testing.T) {
	requireUnixSocket(t)

	path := filepath.Join(t.TempDir(), "peercred.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	dialed := make(chan net.Conn, 1)
	dialErr := make(chan error, 1)
	go func() {
		c, derr := net.Dial("unix", path)
		if derr != nil {
			dialErr <- derr
			return
		}
		dialed <- c
	}()

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer server.Close()

	select {
	case c := <-dialed:
		defer c.Close()
	case derr := <-dialErr:
		t.Fatalf("Dial: %v", derr)
	}

	pid, uid, err := GetPeerCredentials(server)
	if err != nil {
		t.Fatalf("GetPeerCredentials: %v", err)
	}
	if uid != os.Getuid() {
		t.Errorf("peer uid = %d, want %d (this process's uid)", uid, os.Getuid())
	}
	if pid <= 0 {
		t.Errorf("peer pid = %d, want > 0", pid)
	}
}

// TestGetPeerCredentialsNonUnix confirms a non-Unix connection is rejected.
func TestGetPeerCredentialsNonUnix(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if _, _, err := GetPeerCredentials(c1); err == nil {
		t.Fatal("GetPeerCredentials must error for a non-unix connection")
	}
}
