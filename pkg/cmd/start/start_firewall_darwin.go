//go:build darwin

package start

import (
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// setupHostFirewall is a no-op on macOS.
// Phase 6 will add pfctl-based DNS redirect rules here.
func setupHostFirewall(_ io.Writer, _ *factory.Factory, _ *config.Instance, _ string) error {
	return nil
}
