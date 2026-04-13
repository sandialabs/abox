// Package rpc provides shared gRPC utilities for Unix socket communication.
package rpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sandialabs/abox/internal/logging"
)

// UnixListen creates a net.Listener on a Unix socket with restrictive permissions.
// Returns an error if the socket path already exists - callers should use unique
// paths (e.g., with random suffixes) to avoid conflicts with stale sockets.
// For fixed paths that may have stale sockets from crashes, use UnixListenWithStaleCheck.
func UnixListen(path string) (net.Listener, error) {
	// Set restrictive umask before creating socket
	oldUmask := syscall.Umask(0o077)
	listener, err := net.Listen("unix", path)
	syscall.Umask(oldUmask)

	return listener, err
}

// UnixListenWithStaleCheck creates a net.Listener, handling stale sockets from crashes.
// If a socket exists, it tries to connect - if connection fails, the socket is stale
// and safe to remove. If connection succeeds, another process owns it and we error.
func UnixListenWithStaleCheck(path string) (net.Listener, error) {
	// First try to listen directly
	oldUmask := syscall.Umask(0o077)
	listener, err := net.Listen("unix", path)
	syscall.Umask(oldUmask)

	if err == nil {
		return listener, nil
	}

	// If socket exists, check if it's stale
	if _, statErr := os.Stat(path); statErr != nil {
		// Socket doesn't exist, return original error
		return nil, err
	}

	// Try to connect to see if something is listening
	conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		// Something is listening - socket is in use
		conn.Close()
		return nil, fmt.Errorf("socket %s is already in use by another process", path)
	}

	// Connection failed - socket is stale, safe to remove
	logging.Debug("removed stale socket", "path", path)
	if removeErr := os.Remove(path); removeErr != nil {
		return nil, fmt.Errorf("failed to remove stale socket: %w", removeErr)
	}

	// Retry listen
	oldUmask = syscall.Umask(0o077)
	listener, err = net.Listen("unix", path)
	syscall.Umask(oldUmask)

	if err == nil {
		logging.Debug("created unix listener", "path", path)
	}

	return listener, err
}

// UnixDial connects to a gRPC server over a Unix socket.
func UnixDial(path string) (*grpc.ClientConn, error) {
	return UnixDialContext(context.Background(), path)
}

// UnixDialContext connects to a gRPC server over a Unix socket with context.
func UnixDialContext(ctx context.Context, path string) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		// Strip the unix:// prefix that gRPC adds to the address
		socketPath := strings.TrimPrefix(addr, "unix://")
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}

	return grpc.NewClient(
		"unix://"+path,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

// uidCheckListener wraps a net.Listener and verifies peer UID on accept.
type uidCheckListener struct {
	net.Listener
	allowedUID int
}

// Accept accepts a connection and verifies the peer UID matches the allowed value.
func (l *uidCheckListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	_, uid, err := GetPeerCredentials(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to get peer credentials: %w", err)
	}

	if uid != l.allowedUID {
		conn.Close()
		return nil, fmt.Errorf("connection rejected: UID %d not allowed (expected %d)", uid, l.allowedUID)
	}

	return conn, nil
}

// UnixListenWithStaleAndUIDCheck creates a net.Listener that handles stale sockets
// and verifies peer UID on all connections. This combines the stale socket handling
// of UnixListenWithStaleCheck with UID verification for defense-in-depth.
//
// Unlike UnixListenWithUIDCheck (designed for root-owned sockets), this function:
//  1. Creates the socket with restrictive permissions (0o600 via umask 0o077)
//  2. Handles stale sockets from previous crashes
//  3. Verifies peer UID on every connection as defense-in-depth
//
// This is suitable for daemons that run as the user (not root) and want to ensure
// only the same user can connect, even if socket permissions were somehow modified.
func UnixListenWithStaleAndUIDCheck(path string, allowedUID int) (net.Listener, error) {
	listener, err := UnixListenWithStaleCheck(path)
	if err != nil {
		return nil, err
	}

	return &uidCheckListener{
		Listener:   listener,
		allowedUID: allowedUID,
	}, nil
}

// UnixListenWithUIDCheck creates a net.Listener that verifies peer UID.
// Only connections from the specified UID will be accepted.
//
// # Security Model
//
// The socket is created by the privilege helper which runs as root, so it's
// owned by root:root. We chmod to 0o666 because:
//  1. The non-root abox client process needs to connect
//  2. chown would require knowing the client UID at socket creation time
//  3. chgrp to a shared group would require additional system configuration
//
// Security is enforced through multiple layers:
//  1. UID check via SO_PEERCRED - kernel-level check rejects connections from other users
//  2. Token authentication - 256-bit cryptographically random token required for all
//     privileged operations (Ping is exempt for health checks)
//  3. The token is transmitted via stdin pipe from parent to helper, so it's not
//     visible in process arguments, environment variables, or /proc
//  4. Token comparison uses constant-time algorithm to prevent timing attacks
//
// This layered approach ensures that even with world-accessible socket permissions,
// only the specific process that spawned the helper can make authenticated RPC calls.
func UnixListenWithUIDCheck(path string, allowedUID int) (net.Listener, error) {
	listener, err := UnixListen(path)
	if err != nil {
		return nil, err
	}

	// chmod 0o666: See security model documentation above.
	// TL;DR: Socket owned by root, client runs as non-root, security via UID + token.
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // socket needs 0o666: security enforced via UID + token (see comment above)
		_ = listener.Close()
		return nil, fmt.Errorf("failed to chmod socket: %w", err)
	}

	// Set socket ownership to the client user so that external helper socket
	// validation (which checks socket owner matches the current user) passes.
	if err := os.Chown(path, allowedUID, -1); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("failed to chown socket: %w", err)
	}

	return &uidCheckListener{
		Listener:   listener,
		allowedUID: allowedUID,
	}, nil
}
