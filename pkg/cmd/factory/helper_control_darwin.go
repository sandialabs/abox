//go:build darwin

package factory

import (
	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
)

// newHelperControl returns the Pf-service lifecycle client on macOS: the darwin
// helper registers only the Pf service, so Ping/Shutdown must go through it.
func newHelperControl(conn *grpc.ClientConn, token string) helperControl {
	return rpc.NewPfClientWithToken(conn, token)
}
