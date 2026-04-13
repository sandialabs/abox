package rpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// tokenPrivilegeClient wraps a PrivilegeClient and adds the auth token to each request.
type tokenPrivilegeClient struct {
	PrivilegeClient
	token string
}

// NewPrivilegeClientWithToken creates a PrivilegeClient that includes the auth token
// in the metadata of each RPC call.
func NewPrivilegeClientWithToken(conn grpc.ClientConnInterface, token string) PrivilegeClient {
	return &tokenPrivilegeClient{
		PrivilegeClient: NewPrivilegeClient(conn),
		token:           token,
	}
}

// withToken returns a context with the auth token in metadata.
func (c *tokenPrivilegeClient) withToken(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", c.token)
}

// Ping is allowed without auth, but we still add the token for consistency.
func (c *tokenPrivilegeClient) Ping(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*StringMsg, error) {
	return c.PrivilegeClient.Ping(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) Shutdown(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.Shutdown(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) QemuImgCreate(ctx context.Context, in *QemuImgReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.QemuImgCreate(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) Chmod(ctx context.Context, in *ChmodReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.Chmod(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) MkdirAll(ctx context.Context, in *MkdirReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.MkdirAll(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) RemoveAll(ctx context.Context, in *PathReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.RemoveAll(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) CopyFile(ctx context.Context, in *CopyReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.CopyFile(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) UfwAdd(ctx context.Context, in *UfwReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.UfwAdd(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) UfwRemove(ctx context.Context, in *UfwReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.UfwRemove(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) UfwStatus(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*UfwStatusResp, error) {
	return c.PrivilegeClient.UfwStatus(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) IptablesAdd(ctx context.Context, in *IptablesReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.IptablesAdd(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) IptablesRemove(ctx context.Context, in *IptablesReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.IptablesRemove(c.withToken(ctx), in, opts...)
}

func (c *tokenPrivilegeClient) IptablesFlush(ctx context.Context, in *IptablesFlushReq, opts ...grpc.CallOption) (*Empty, error) {
	return c.PrivilegeClient.IptablesFlush(c.withToken(ctx), in, opts...)
}
