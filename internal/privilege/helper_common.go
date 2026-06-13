package privilege

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// resolvedCommands holds absolute paths for external commands.
// These are resolved once at startup and cached for the process lifetime.
var resolvedCommands struct {
	mu       sync.RWMutex
	resolved bool
	paths    map[string]string
}

// safeEnv is the minimal environment for child processes.
// Defense-in-depth: even though the setuid binary clears its own environment
// at startup, explicitly setting cmd.Env prevents any env vars set by Go
// runtime or library code from leaking to iptables, qemu-img, pfctl, etc.
var safeEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// resolveCommandList resolves absolute paths for the given commands.
// Called by platform-specific ResolveCommands() with the appropriate command list.
func resolveCommandList(commands []struct {
	name     string
	required bool
}) error {
	resolvedCommands.mu.Lock()
	defer resolvedCommands.mu.Unlock()

	if resolvedCommands.resolved {
		return nil
	}

	resolvedCommands.paths = make(map[string]string)

	for _, entry := range commands {
		path, err := exec.LookPath(entry.name)
		if err != nil {
			if entry.required {
				return fmt.Errorf("required command %q not found in PATH: %w", entry.name, err)
			}
			continue
		}
		// Use absolute path but do NOT resolve symlinks.
		// iptables is a multi-call binary (xtables-nft-multi) that uses
		// argv[0] to determine behavior. Resolving symlinks breaks it.
		abs, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for %q: %w", entry.name, err)
		}
		resolvedCommands.paths[entry.name] = abs
	}

	resolvedCommands.resolved = true
	return nil
}

// cmdPath returns the absolute path for a command, falling back to the bare
// name if ResolveCommands hasn't been called (backwards compatibility).
func cmdPath(name string) string {
	resolvedCommands.mu.RLock()
	defer resolvedCommands.mu.RUnlock()

	if resolvedCommands.resolved {
		if p, ok := resolvedCommands.paths[name]; ok && p != "" {
			return p
		}
	}
	return name
}

// safeCommand creates an exec.Cmd with an explicit minimal environment.
// Platform-specific credential overrides are applied via platformSafeCommand.
func safeCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = safeEnv
	platformSafeCommand(cmd)
	return cmd
}

// shutdownState holds the gRPC server for coordinated shutdown.
var shutdownState struct {
	mu     sync.Mutex
	server *grpc.Server
}

// gracefulShutdown initiates a graceful shutdown of the gRPC server.
// Called by platform-specific Shutdown RPC implementations.
func gracefulShutdown() {
	go func() {
		// Brief delay to allow the RPC response to be sent
		time.Sleep(50 * time.Millisecond)

		shutdownState.mu.Lock()
		srv := shutdownState.server
		shutdownState.mu.Unlock()

		if srv != nil {
			srv.GracefulStop()
		}
	}()
}

// RunHelper runs the privileged helper gRPC server.
// It listens on a Unix socket and handles privileged operations.
// Authentication is token-based: the token is read from stdin on startup,
// and all RPC calls (except Ping) must include the token in metadata.
// The allowedUID parameter restricts socket connections to that UID.
// The register callback is called to register the platform-specific PrivilegeServer.
func RunHelper(socketPath string, allowedUID int, register func(server *grpc.Server, allowedUID int)) error {
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
	defer os.Remove(socketPath)

	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			tokenAuthInterceptor(token),
			auditInterceptor(),
		),
	)
	register(server, allowedUID)

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
		// Allow Ping without auth for health checks
		if info.FullMethod == rpc.Privilege_Ping_FullMethodName {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		tokens := md.Get("authorization")
		if len(tokens) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization token")
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(expectedToken)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization token")
		}

		return handler(ctx, req)
	}
}

// auditInterceptor returns a gRPC interceptor that logs every RPC call to syslog.
// This provides an audit trail for all privileged operations, replacing the
// sudo audit trail that would otherwise be lost with the setuid helper.
func auditInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Skip auditing Ping (health check noise)
		if info.FullMethod == rpc.Privilege_Ping_FullMethodName {
			return handler(ctx, req)
		}

		resp, err := handler(ctx, req)

		if err != nil {
			errMsg := err.Error()
			if len(errMsg) > 200 {
				errMsg = errMsg[:200]
			}
			logging.Audit("privilege-helper.rpc", "method", info.FullMethod, "result", "error", "error", errMsg)
		} else {
			logging.Audit("privilege-helper.rpc", "method", info.FullMethod, "result", "success")
		}

		return resp, err
	}
}

// validateDiskSize validates a disk size string (e.g., "20G", "100M").
func validateDiskSize(size string) error {
	if len(size) < 2 {
		return fmt.Errorf("invalid disk size: %s", size)
	}

	suffix := size[len(size)-1]
	if suffix != 'G' && suffix != 'T' {
		return fmt.Errorf("disk size must use G or T suffix: %s", size)
	}

	numPart := size[:len(size)-1]
	num, err := strconv.Atoi(numPart)
	if err != nil || num <= 0 {
		return fmt.Errorf("disk size must be a positive integer: %s", size)
	}

	switch suffix {
	case 'T':
		if num > 10 {
			return fmt.Errorf("disk size must be at most 10T: %s", size)
		}
	case 'G':
		if num > 10240 {
			return fmt.Errorf("disk size must be at most 10T: %s", size)
		}
	}

	return nil
}
