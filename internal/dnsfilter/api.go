package dnsfilter

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/rpc"
)

// APIServer handles gRPC API requests for DNS filtering.
// It implements both DNSFilterServer and AllowlistServer interfaces.
type APIServer struct {
	rpc.UnimplementedDNSFilterServer
	rpc.UnimplementedAllowlistServer
	*filterbase.BaseAPIServer
	server *Server
}

// NewAPIServer creates a new API server.
func NewAPIServer(socketPath string, filter *allowlist.Filter, server *Server, loader *allowlist.Loader) *APIServer {
	return &APIServer{
		BaseAPIServer: filterbase.NewBaseAPIServer(socketPath, filter, server, loader),
		server:        server,
	}
}

// Start starts the gRPC API server.
func (a *APIServer) Start() error {
	return a.BaseAPIServer.Start(func(s *grpc.Server) {
		rpc.RegisterDNSFilterServer(s, a)
		rpc.RegisterAllowlistServer(s, a)
	})
}

// Status returns the server status.
func (a *APIServer) Status(_ context.Context, _ *rpc.Empty) (*rpc.DNSStatus, error) {
	stats := a.server.GetStats()

	return &rpc.DNSStatus{
		Mode:           a.server.GetMode(),
		Domains:        int32(a.Filter.Count()), //nolint:gosec // domain count is bounded
		TotalQueries:   stats.TotalQueries,
		AllowedQueries: stats.AllowedQueries,
		BlockedQueries: stats.BlockedQueries,
		Uptime:         time.Since(stats.StartTime).Round(time.Second).String(),
		DnsPort:        int32(a.server.GetListenPort()), //nolint:gosec // port is 0-65535
	}, nil
}

// Explicitly delegate to BaseAPIServer to resolve ambiguity with UnimplementedDNSFilterServer

func (a *APIServer) Add(ctx context.Context, req *rpc.DomainReq) (*rpc.StringMsg, error) {
	return a.BaseAPIServer.Add(ctx, req)
}

func (a *APIServer) Remove(ctx context.Context, req *rpc.DomainReq) (*rpc.StringMsg, error) {
	return a.BaseAPIServer.Remove(ctx, req)
}

func (a *APIServer) List(ctx context.Context, req *rpc.Empty) (*rpc.DomainList, error) {
	return a.BaseAPIServer.List(ctx, req)
}

func (a *APIServer) Reload(ctx context.Context, req *rpc.Empty) (*rpc.StringMsg, error) {
	return a.BaseAPIServer.Reload(ctx, req)
}

func (a *APIServer) SetMode(ctx context.Context, req *rpc.ModeReq) (*rpc.StringMsg, error) {
	return a.BaseAPIServer.SetMode(ctx, req)
}

func (a *APIServer) Profile(ctx context.Context, req *rpc.ProfileReq) (*rpc.ProfileResp, error) {
	return a.BaseAPIServer.Profile(ctx, req)
}

func (a *APIServer) SetLogLevel(ctx context.Context, req *rpc.LogLevelReq) (*rpc.StringMsg, error) {
	return a.BaseAPIServer.SetLogLevel(ctx, req)
}

func (a *APIServer) GetLogLevel(ctx context.Context, req *rpc.Empty) (*rpc.LogLevelResp, error) {
	return a.BaseAPIServer.GetLogLevel(ctx, req)
}

func (a *APIServer) Shutdown(ctx context.Context, req *rpc.Empty) (*rpc.Empty, error) {
	return a.BaseAPIServer.Shutdown(ctx, req)
}
