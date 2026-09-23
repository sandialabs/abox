package privilege

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// ResolveCommands resolves the absolute paths for the external commands the
// platform's privileged helper invokes. This should be called once at startup.
// In setuid context, PATH is sanitized but an absolute path provides
// defense-in-depth. The per-platform work happens in resolvePlatformCommands
// (see helper_linux.go / helper_darwin.go).
func ResolveCommands() error {
	return resolvePlatformCommands()
}

// RunHelper runs the privileged egress helper gRPC server.
// It listens on a Unix socket and handles privileged operations.
// Authentication is token-based: the token is read from stdin on startup,
// and all RPC calls (except Ping) must include the token in metadata.
// The allowedUID parameter restricts socket connections to that UID.
func RunHelper(socketPath string, allowedUID int) error {
	// Verify we're running as root
	if os.Geteuid() != 0 {
		return errors.New("privilege-helper must be run as root (via pkexec/sudo); this is an internal command used by abox, do not run it directly")
	}

	if allowedUID < 0 {
		return errors.New("--allowed-uid is required for security")
	}

	// Ensure command paths are resolved (idempotent due to resolved flag).
	// The setuid binary calls ResolveCommands() explicitly before RunHelper(),
	// but the cobra subcommand path may not, so resolve here as a safety net.
	if err := ResolveCommands(); err != nil {
		return fmt.Errorf("failed to resolve command paths: %w", err)
	}

	// Read token from stdin (sent by parent process)
	token, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read token from stdin: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("empty token received")
	}
	// Minimum 32 characters (128 bits) for security; we generate 64 hex chars (256 bits)
	if len(token) < 32 {
		return errors.New("token too short (minimum 32 characters)")
	}
	if len(token) > 256 {
		return errors.New("token too long (maximum 256 characters)")
	}

	listener, err := rpc.UnixListenWithUIDCheck(socketPath, allowedUID)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}
	defer func() { _ = listener.Close() }()
	// Remove the socket on shutdown via a directory-fd-relative unlink (Linux) so
	// this root-privileged cleanup cannot be redirected by a parent-directory swap.
	// Non-Linux falls back to a path-based remove.
	defer func() { _ = removeSocket(socketPath) }()

	// Record helper startup with the caller UID. This is emitted here (not only in
	// the Linux setuid main.go) so the darwin path — where the helper is launched
	// as `abox privilege-helper` via sudo and never runs main.go — also produces a
	// UID-attributed startup record. It is the anchor the per-RPC audit lines refer
	// to, and it is now duplicated by caller_uid on every RPC line below.
	logging.Audit("privilege-helper.start",
		"action", "privilege-helper.start",
		"caller_uid", allowedUID,
		"pid", os.Getpid(),
		"socket", socketPath,
	)

	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			tokenAuthInterceptor(token),
			auditInterceptor(allowedUID),
		),
	)
	// Register the platform's privileged services (see helper_linux.go /
	// helper_darwin.go): Egress (iptables) on Linux, Pf (pfctl) on darwin.
	registerHelperServices(server, allowedUID)

	// Store shutdown state under mutex for coordinated shutdown
	shutdownState.mu.Lock()
	shutdownState.server = server
	shutdownState.mu.Unlock()

	return server.Serve(listener)
}

// tokenAuthInterceptor returns a gRPC interceptor that validates the auth token.
// Ping is allowed without authentication to enable health checks.
func tokenAuthInterceptor(expectedToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Allow Ping without auth for health checks. The helper registers a
		// different service per platform (Egress/iptables on Linux, Pf/pfctl on
		// darwin), so match both services' Ping method.
		if info.FullMethod == rpc.Egress_Ping_FullMethodName ||
			info.FullMethod == rpc.Pf_Ping_FullMethodName {
			return handler(ctx, req)
		}

		// Audit every authentication denial: these are the probe/brute-force
		// attempts against the privileged socket that a security audit trail must
		// capture. The token itself is never logged. This runs before the
		// auditInterceptor in the chain, so a denial would otherwise leave no audit
		// record at all.
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			logging.Audit("privilege-helper.auth-denied", "method", info.FullMethod, "reason", "missing metadata")
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		tokens := md.Get("authorization")
		if len(tokens) == 0 {
			logging.Audit("privilege-helper.auth-denied", "method", info.FullMethod, "reason", "missing authorization token")
			return nil, status.Error(codes.Unauthenticated, "missing authorization token")
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(expectedToken)) != 1 {
			logging.Audit("privilege-helper.auth-denied", "method", info.FullMethod, "reason", "invalid authorization token")
			return nil, status.Error(codes.Unauthenticated, "invalid authorization token")
		}

		return handler(ctx, req)
	}
}

// auditInterceptor returns a gRPC interceptor that logs every RPC call to the
// platform audit sink. This provides an audit trail for all privileged
// operations, replacing the sudo audit trail that would otherwise be lost with
// the setuid helper. Every line carries the caller UID so a privileged action is
// attributable even if the startup record (see RunHelper) has aged out of the
// sink — this matters on darwin, whose unified-log sink is best-effort.
func auditInterceptor(callerUID int) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Skip auditing Ping (health check noise) for whichever service this
		// platform's helper registered (Egress on Linux, Pf on darwin).
		if info.FullMethod == rpc.Egress_Ping_FullMethodName ||
			info.FullMethod == rpc.Pf_Ping_FullMethodName {
			return handler(ctx, req)
		}

		resp, err := handler(ctx, req)

		if err != nil {
			errMsg := err.Error()
			if len(errMsg) > 200 {
				// Trim to 200 bytes, then repair any rune split at the boundary so the
				// audit record is always valid UTF-8 (pfctl/iptables output or paths
				// may contain multi-byte runes).
				errMsg = strings.ToValidUTF8(errMsg[:200], "")
			}
			logging.Audit("privilege-helper.rpc", "method", info.FullMethod, "caller_uid", callerUID, "result", "error", "error", errMsg)
		} else {
			logging.Audit("privilege-helper.rpc", "method", info.FullMethod, "caller_uid", callerUID, "result", "success")
		}

		return resp, err
	}
}

// shutdownState holds the gRPC server for coordinated shutdown.
var shutdownState struct {
	mu     sync.Mutex
	server *grpc.Server
}
