//go:build linux

package start

import (
	"context"
	"io"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// recoverFirewall is a no-op on Linux. iptables DNS-redirect rules are set up
// pre-boot via setupHostFirewall and traffic enforcement lives in the libvirt
// nwfilter baked into the running domain, neither of which the already-running
// start path needs to repair.
func recoverFirewall(_ context.Context, _ io.Writer, _ *factory.Factory, _ backend.Backend, _ string, _ *config.Instance) error {
	return nil
}
