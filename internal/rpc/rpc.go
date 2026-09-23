// Package rpc provides shared gRPC utilities for Unix socket communication.
package rpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sandialabs/abox/internal/logging"
)

// unixListen creates a net.Listener on a Unix socket with restrictive
// permissions (0o600 where the platform honors umask; see listenUnixRestrictive).
// It returns an error if the socket path already exists. It performs NO peer
// authentication, so it is unexported: daemons must use UnixListenSecure (which
// adds a peer-UID check) and the privilege helper uses UnixListenWithUIDCheck
// (cross-UID, root-owned socket). Only those two wrappers may build on it.
func unixListen(path string) (net.Listener, error) {
	return listenUnixRestrictive(path)
}

// unixListenWithStaleCheck creates a net.Listener, handling stale sockets from
// crashes. If a socket exists, it tries to connect — if the connection fails the
// socket is stale and safe to remove; if it succeeds another process owns it and
// we error. It performs NO peer authentication and is unexported for the same
// reason as unixListen: UnixListenSecure wraps it with a peer-UID check.
func unixListenWithStaleCheck(path string) (net.Listener, error) {
	// First try to listen directly
	listener, err := listenUnixRestrictive(path)
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
	listener, err = listenUnixRestrictive(path)
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
//
// A rejected or unverifiable peer must never stop the server: grpc.Server.Serve
// treats any non-temporary Accept error as fatal and returns, which would tear
// down the whole (privileged) listener over a single stray connection. So a
// peer-credential failure or UID mismatch drops that one connection and the
// loop continues; only a genuine error from the underlying listener (e.g. it
// was closed) is propagated to the caller.
func (l *uidCheckListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		_, uid, err := GetPeerCredentials(conn)
		if err != nil {
			conn.Close()
			logging.Warn("rejecting helper connection: failed to get peer credentials", "error", err)
			// Audit the denial: a connection to a UID-gated socket that cannot be
			// attributed to a peer is a security-relevant event the audit trail must
			// capture (Warn alone does not reach the audit sink on every platform).
			logging.Audit("rpc.peer-rejected", "reason", "peer credentials unavailable", "expected_uid", l.allowedUID)
			continue
		}

		if uid != l.allowedUID {
			conn.Close()
			logging.Warn("rejecting helper connection: UID not allowed", "uid", uid, "expected", l.allowedUID)
			// Audit the denial: a foreign UID connecting to the (privileged) socket
			// is exactly the probe a security audit trail must record.
			logging.Audit("rpc.peer-rejected", "reason", "uid not allowed", "uid", uid, "expected_uid", l.allowedUID)
			continue
		}

		return conn, nil
	}
}

// UnixListenSecure is the default listener for abox daemons that run as the
// invoking user (DNS/HTTP filters, monitor). It is secure by construction:
//  1. Creates the socket with restrictive permissions (0o600 via umask 0o077)
//  2. Handles stale sockets left by a previous crash
//  3. Verifies the peer UID against the current process UID on EVERY connection,
//     so only the same user can connect even if the socket mode were modified.
//
// The allowed UID is fixed to os.Getuid() internally — there is no UID parameter
// to pass incorrectly. Cross-UID sockets (the root-owned privilege helper, where
// the client UID differs from the listener UID) must use UnixListenWithUIDCheck
// instead; that is the only other exported listener, and the only one that skips
// the self-UID default.
func UnixListenSecure(path string) (net.Listener, error) {
	listener, err := unixListenWithStaleCheck(path)
	if err != nil {
		return nil, err
	}

	return &uidCheckListener{
		Listener:   listener,
		allowedUID: os.Getuid(),
	}, nil
}

// UnixListenWithUIDCheck creates a net.Listener that verifies peer UID.
// Only connections from the specified UID will be accepted.
//
// # Security Model
//
// The socket is created by the privilege helper which runs as root, so it's
// owned by root:root. The socket mode is platform-split (socketPeerCheckMode; see
// socket_mode_{darwin,other}.go and the inline note below):
//   - Linux: 0o666, because the non-root abox client must connect and chown would
//     require knowing the client UID at socket-creation time (security rests on
//     SO_PEERCRED + token, below).
//   - darwin: 0o600 + chown to the allowed UID, since the spawn path knows it.
//
// Security is enforced through multiple layers:
//  1. UID check via SO_PEERCRED - kernel-level check rejects connections from other users
//  2. Token authentication - 256-bit cryptographically random token required for all
//     privileged operations (Ping is exempt for health checks)
//  3. The token is transmitted via stdin pipe from parent to helper, so it's not
//     visible in process arguments, environment variables, or /proc
//  4. Token comparison uses constant-time algorithm to prevent timing attacks
//
// This layered approach ensures that even on Linux's world-accessible socket
// permissions, only the specific process that spawned the helper can make
// authenticated RPC calls.
func UnixListenWithUIDCheck(path string, allowedUID int) (net.Listener, error) {
	listener, err := unixListen(path)
	if err != nil {
		return nil, err
	}

	// Apply the socket mode (platform-split socketPeerCheckMode) and owner. The
	// implementation is platform-specific: on Linux it operates on the listener's
	// file descriptor (fchmod/fchown) with an fstat verification, closing the
	// path-based TOCTOU window that a caller-controlled --socket could exploit
	// against the root-privileged helper; darwin keeps the path-based form. See
	// applySocketPermissions in socket_perm_{linux,other}.go.
	if err := applySocketPermissions(listener, path, socketPeerCheckMode, allowedUID); err != nil {
		_ = listener.Close()
		return nil, err
	}

	return &uidCheckListener{
		Listener:   listener,
		allowedUID: allowedUID,
	}, nil
}
