//go:build !darwin

package factory

import (
	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
)

// newHelperControl returns the Egress-service lifecycle client on Linux (and
// other non-darwin platforms): the helper registers the Egress service, whose
// Ping/Shutdown drive helper readiness and graceful shutdown.
func newHelperControl(conn *grpc.ClientConn, token string) helperControl {
	return rpc.NewEgressClientWithToken(conn, token)
}
