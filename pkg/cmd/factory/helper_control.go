package factory

import (
	"context"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
)

// helperControl is the OS-agnostic lifecycle surface (Ping/Shutdown) of the
// privilege helper. Both the Egress service (Linux) and the Pf service (macOS)
// expose these two methods with identical signatures, so the factory can drive
// helper readiness and graceful shutdown without knowing which service the
// helper actually registered. The per-OS constructor newHelperControl picks the
// right client; see helper_control_darwin.go / helper_control_other.go.
//
// This decouples helper lifecycle from the Egress service specifically: on
// macOS the helper registers ONLY Pf, so an Egress-based Ping/Shutdown would
// fail as Unimplemented and break helper startup.
type helperControl interface {
	Ping(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.StringMsg, error)
	Shutdown(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.Empty, error)
}
