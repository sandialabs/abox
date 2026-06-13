//go:build linux

package start

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// setupPostBootFirewall is a no-op on Linux.
// iptables rules are set up pre-boot via setupHostFirewall.
func setupPostBootFirewall(_ io.Writer, _ *factory.Factory, _ *config.Instance, _ string, _ string) error {
	return nil
}
