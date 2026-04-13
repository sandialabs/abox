package cloudinit

import (
	_ "embed"
	"fmt"

	"github.com/sandialabs/abox/internal/validation"
)

//go:embed templates/bootcmd.yaml.tmpl
var bootcmdTemplate string

// DNSContributor produces cloud-init bootcmd content for DNS configuration.
type DNSContributor struct {
	Gateway string // Gateway IP address for DNS configuration
}

// Contribute returns the bootcmd section for DNS configuration.
// Returns nil when Gateway is empty (DNS not configured).
func (c *DNSContributor) Contribute() (*Contribution, error) {
	if c.Gateway == "" {
		return nil, nil //nolint:nilnil // nil means no contribution when DNS not configured
	}

	if err := validation.ValidateIPv4(c.Gateway); err != nil {
		return nil, fmt.Errorf("DNS contributor: %w", err)
	}

	bootcmdContent, err := RenderTemplate("bootcmd", bootcmdTemplate, c)
	if err != nil {
		return nil, err
	}

	return &Contribution{
		Bootcmd: bootcmdContent,
	}, nil
}
