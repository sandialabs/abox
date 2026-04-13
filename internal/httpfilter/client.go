package httpfilter

import (
	"context"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// ClientContext returns a context with the standard timeout for HTTP filter client operations.
func ClientContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout.HTTPClient)
}

// Client wraps the gRPC client connection for HTTP filter and allowlist operations.
type Client struct {
	conn            *grpc.ClientConn
	httpClient      rpc.HTTPFilterClient
	allowlistClient rpc.AllowlistClient
}

// Dial connects to the HTTP filter server at the given socket path.
func Dial(socketPath string) (*Client, error) {
	conn, err := rpc.UnixDial(socketPath)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:            conn,
		httpClient:      rpc.NewHTTPFilterClient(conn),
		allowlistClient: rpc.NewAllowlistClient(conn),
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Client returns the underlying HTTP filter gRPC client.
func (c *Client) Client() rpc.HTTPFilterClient {
	return c.httpClient
}

// AllowlistClient returns the underlying Allowlist gRPC client.
func (c *Client) AllowlistClient() rpc.AllowlistClient {
	return c.allowlistClient
}

// StartKeyLog tells the HTTP filter to begin writing TLS session keys to the given path.
func (c *Client) StartKeyLog(ctx context.Context, path string) error {
	_, err := c.httpClient.StartKeyLog(ctx, &rpc.KeyLogReq{Path: path})
	return err
}

// StopKeyLog tells the HTTP filter to stop writing TLS session keys.
func (c *Client) StopKeyLog(ctx context.Context) error {
	_, err := c.httpClient.StopKeyLog(ctx, &rpc.Empty{})
	return err
}
