package dnsfilter

import (
	"context"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// ClientContext returns a context with the standard timeout for DNS filter client operations.
func ClientContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout.DNSClient)
}

// Client wraps the gRPC client connection for DNS filter and allowlist operations.
type Client struct {
	conn            *grpc.ClientConn
	dnsClient       rpc.DNSFilterClient
	allowlistClient rpc.AllowlistClient
}

// Dial connects to the DNS filter server at the given socket path.
func Dial(socketPath string) (*Client, error) {
	conn, err := rpc.UnixDial(socketPath)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:            conn,
		dnsClient:       rpc.NewDNSFilterClient(conn),
		allowlistClient: rpc.NewAllowlistClient(conn),
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Client returns the underlying DNS filter gRPC client.
func (c *Client) Client() rpc.DNSFilterClient {
	return c.dnsClient
}

// AllowlistClient returns the underlying Allowlist gRPC client.
func (c *Client) AllowlistClient() rpc.AllowlistClient {
	return c.allowlistClient
}
