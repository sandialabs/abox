//go:build darwin

package start

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// setupHostFirewall is a no-op on macOS.
// pfctl DNS redirect rules are set up post-boot in setupPostBootFirewall
// because vmnet assigns VM IPs dynamically via DHCP.
func setupHostFirewall(_ io.Writer, _ *factory.Factory, _ *config.Instance, _ string) error {
	return nil
}
