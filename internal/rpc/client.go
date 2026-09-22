package rpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// tokenEgressClient wraps an EgressClient and adds the auth token to each request.
type tokenEgressClient struct {
	EgressClient
	token string
}

// NewEgressClientWithToken creates an EgressClient that includes the auth token
// in the metadata of each RPC call.
func NewEgressClientWithToken(conn grpc.ClientConnInterface, token string) EgressClient {
	return &tokenEgressClient{
		EgressClient: NewEgressClient(conn),
		token:        token,
	}
}

// withToken returns a context with the auth token in metadata.
func (c *tokenEgressClient) withToken(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", c.token)
}

// Ping is allowed without auth, but we still add the token for consistency.
func (c *tokenEgressClient) Ping(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*StringMsg, error) {
	return c.EgressClient.Ping(c.withToken(ctx), in, opts...)
}

func (c *tokenEgressClient) Shutdown(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*Empty, error) {
	return c.EgressClient.Shutdown(c.withToken(ctx), in, opts...)
}

func (c *tokenEgressClient) EnsureStorageRoot(ctx context.Context, in *EnsureStorageRootReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.EgressClient.EnsureStorageRoot(c.withToken(ctx), in, opts...)
}

func (c *tokenEgressClient) Apply(ctx context.Context, in *EgressReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.EgressClient.Apply(c.withToken(ctx), in, opts...)
}

func (c *tokenEgressClient) Remove(ctx context.Context, in *EgressReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.EgressClient.Remove(c.withToken(ctx), in, opts...)
}

func (c *tokenEgressClient) Verify(ctx context.Context, in *EgressReq, opts ...grpc.CallOption) (*BoolMsg, error) {
	return c.EgressClient.Verify(c.withToken(ctx), in, opts...)
}

// tokenPfClient wraps a PfClient and adds the auth token to each request. Unlike
// the egress Ping (which is auth-exempt), every Pf method — including Ping —
// requires the token, so an untokened client would fail on every call. This
// wrapper is therefore mandatory for the macOS pfctl surface.
type tokenPfClient struct {
	PfClient
	token string
}

// NewPfClientWithToken creates a PfClient that includes the auth token in the
// metadata of each RPC call. Mirrors NewEgressClientWithToken.
func NewPfClientWithToken(conn grpc.ClientConnInterface, token string) PfClient {
	return &tokenPfClient{
		PfClient: NewPfClient(conn),
		token:    token,
	}
}

// withToken returns a context with the auth token in metadata.
func (c *tokenPfClient) withToken(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", c.token)
}

func (c *tokenPfClient) Ping(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*StringMsg, error) {
	return c.PfClient.Ping(c.withToken(ctx), in, opts...)
}

func (c *tokenPfClient) Shutdown(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*Empty, error) {
	return c.PfClient.Shutdown(c.withToken(ctx), in, opts...)
}

func (c *tokenPfClient) Enable(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*Empty, error) {
	return c.PfClient.Enable(c.withToken(ctx), in, opts...)
}

func (c *tokenPfClient) LoadAnchor(ctx context.Context, in *PfAnchorReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PfClient.LoadAnchor(c.withToken(ctx), in, opts...)
}

func (c *tokenPfClient) FlushAnchor(ctx context.Context, in *PfInstanceReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PfClient.FlushAnchor(c.withToken(ctx), in, opts...)
}

func (c *tokenPfClient) TeardownConfig(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*Empty, error) {
	return c.PfClient.TeardownConfig(c.withToken(ctx), in, opts...)
}
