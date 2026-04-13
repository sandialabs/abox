// Package filterbase provides shared infrastructure for DNS and HTTP filter services,
// including API servers, daemon setup, traffic logging, status display, and SSRF protection.
package filterbase

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
)

// BaseAPIServer provides shared functionality for filter API servers.
// Embed this in DNS/HTTP API servers to avoid code duplication.
type BaseAPIServer struct {
	allowlist.AllowlistAPIHandler // embedded handler for shared allowlist methods
	socketPath                    string
	grpcServer                    *grpc.Server
}

// NewBaseAPIServer creates a new base API server.
func NewBaseAPIServer(socketPath string, filter *allowlist.Filter, server allowlist.ModeServer, loader *allowlist.Loader) *BaseAPIServer {
	return &BaseAPIServer{
		socketPath: socketPath,
		AllowlistAPIHandler: allowlist.AllowlistAPIHandler{
			Filter: filter,
			Loader: loader,
			Server: server,
		},
	}
}

// Start creates the gRPC server and listener. The register callback is invoked
// to register services before Serve() is called, avoiding the gRPC race where
// RegisterService after Serve causes a fatal error.
func (b *BaseAPIServer) Start(register func(*grpc.Server)) error {
	listener, err := rpc.UnixListenWithStaleCheck(b.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}

	b.grpcServer = grpc.NewServer()
	register(b.grpcServer)

	go func() {
		if err := b.grpcServer.Serve(listener); err != nil {
			logging.Warn("gRPC server stopped", "error", err)
		}
	}()

	return nil
}

// Stop stops the API server.
func (b *BaseAPIServer) Stop() {
	if b.grpcServer != nil {
		b.grpcServer.GracefulStop()
	}
	if err := os.Remove(b.socketPath); err != nil && !os.IsNotExist(err) {
		logging.Warn("failed to remove socket", "path", b.socketPath, "error", err)
	}
}

// SocketPath returns the socket path.
func (b *BaseAPIServer) SocketPath() string {
	return b.socketPath
}

// SetLogLevel sets the log level at runtime.
func (b *BaseAPIServer) SetLogLevel(_ context.Context, req *rpc.LogLevelReq) (*rpc.StringMsg, error) {
	return &rpc.StringMsg{Message: logging.SetLevelString(req.Level)}, nil
}

// GetLogLevel returns the current log level.
func (b *BaseAPIServer) GetLogLevel(_ context.Context, _ *rpc.Empty) (*rpc.LogLevelResp, error) {
	return &rpc.LogLevelResp{Level: logging.GetLevelString()}, nil
}

// Shutdown gracefully shuts down the filter server by sending SIGINT.
func (b *BaseAPIServer) Shutdown(_ context.Context, _ *rpc.Empty) (*rpc.Empty, error) {
	if proc, err := os.FindProcess(os.Getpid()); err == nil {
		_ = proc.Signal(os.Interrupt)
	}
	return &rpc.Empty{}, nil
}

// Add adds a domain to the allowlist (delegates to embedded handler).
func (b *BaseAPIServer) Add(_ context.Context, req *rpc.DomainReq) (*rpc.StringMsg, error) {
	return b.AllowlistAPIHandler.Add(req.Domain)
}

// Remove removes a domain from the allowlist (delegates to embedded handler).
func (b *BaseAPIServer) Remove(_ context.Context, req *rpc.DomainReq) (*rpc.StringMsg, error) {
	return b.AllowlistAPIHandler.Remove(req.Domain)
}

// List returns all domains in the allowlist (delegates to embedded handler).
func (b *BaseAPIServer) List(_ context.Context, _ *rpc.Empty) (*rpc.DomainList, error) {
	return b.AllowlistAPIHandler.List()
}

// Reload reloads the allowlist from file (delegates to embedded handler).
func (b *BaseAPIServer) Reload(_ context.Context, _ *rpc.Empty) (*rpc.StringMsg, error) {
	return b.AllowlistAPIHandler.Reload()
}

// SetMode sets the filtering mode (delegates to embedded handler).
func (b *BaseAPIServer) SetMode(_ context.Context, req *rpc.ModeReq) (*rpc.StringMsg, error) {
	return b.AllowlistAPIHandler.SetMode(req.Mode)
}

// Profile manages the profile log (delegates to embedded handler).
func (b *BaseAPIServer) Profile(_ context.Context, req *rpc.ProfileReq) (*rpc.ProfileResp, error) {
	return b.AllowlistAPIHandler.Profile(req.Subcommand)
}
