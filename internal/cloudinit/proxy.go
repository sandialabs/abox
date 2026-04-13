package cloudinit

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/sandialabs/abox/internal/validation"
)

//go:embed templates/proxy-setup.sh
var proxySetupTemplate string

//go:embed templates/abox-proxy.sh
var proxyProfileTemplate string

//go:embed templates/abox-proxy.env
var proxyEnvFileTemplate string

//go:embed templates/write-file-ca-cert-debian.yaml.tmpl
var writeFileCACertDebianTmpl string

//go:embed templates/write-file-ca-cert-rhel.yaml.tmpl
var writeFileCACertRHELTmpl string

//go:embed templates/write-file-proxy-profile.yaml.tmpl
var writeFileProxyProfileTmpl string

//go:embed templates/write-file-proxy-env.yaml.tmpl
var writeFileProxyEnvTmpl string

//go:embed templates/write-file-proxy-setup.yaml.tmpl
var writeFileProxySetupTmpl string

// writeFileData holds content for write_files YAML template rendering.
type writeFileData struct {
	Content string
}

// ProxyContributor produces cloud-init content for HTTP proxy configuration.
type ProxyContributor struct {
	Gateway  string // Gateway IP address
	HTTPPort int    // HTTP proxy port
	CACert   string // PEM-encoded CA certificate for MITM (optional)
}

// Contribute returns write_files and runcmd content for proxy configuration.
// Returns nil when proxy is not configured.
func (c *ProxyContributor) Contribute() (*Contribution, error) {
	var writeFiles []string
	var runcmd []string

	// Add CA certificate for TLS MITM if provided
	if c.CACert != "" {
		if err := validation.ValidatePEMCertificate(c.CACert); err != nil {
			return nil, fmt.Errorf("invalid CA certificate: %w", err)
		}
		certEntries, err := c.buildCACertFiles()
		if err != nil {
			return nil, err
		}
		writeFiles = append(writeFiles, certEntries...)

		// Add runcmd for CA certificate update
		runcmd = append(runcmd, `  - |
    # Update CA certificates (distro-agnostic)
    if command -v update-ca-trust >/dev/null 2>&1; then
      update-ca-trust
    elif command -v update-ca-certificates >/dev/null 2>&1; then
      update-ca-certificates
    fi`)
	}

	// Add HTTP proxy configuration if HTTPPort is specified
	if c.HTTPPort > 0 && c.Gateway != "" {
		proxyFiles, err := c.buildProxyFiles()
		if err != nil {
			return nil, err
		}
		writeFiles = append(writeFiles, proxyFiles...)
	}

	if len(writeFiles) == 0 && len(runcmd) == 0 {
		return nil, nil //nolint:nilnil // nil means no contribution when proxy not configured
	}

	return &Contribution{
		WriteFiles: writeFiles,
		Runcmd:     runcmd,
	}, nil
}

func (c *ProxyContributor) buildCACertFiles() ([]string, error) {
	data := writeFileData{Content: IndentLines(c.CACert)}
	templates := []struct{ name, tmpl string }{
		{"write-file-ca-cert-debian", writeFileCACertDebianTmpl},
		{"write-file-ca-cert-rhel", writeFileCACertRHELTmpl},
	}
	return renderWriteFiles(templates, data)
}

func (c *ProxyContributor) buildProxyFiles() ([]string, error) {
	if err := validation.ValidateIPv4(c.Gateway); err != nil {
		return nil, fmt.Errorf("proxy contributor: %w", err)
	}
	if c.HTTPPort > 65535 {
		return nil, fmt.Errorf("invalid HTTP port: %d (must be 0-65535)", c.HTTPPort)
	}

	profileContent, err := RenderTemplate("proxy-profile", proxyProfileTemplate, c)
	if err != nil {
		return nil, err
	}
	envFileContent, err := RenderTemplate("proxy-env-file", proxyEnvFileTemplate, c)
	if err != nil {
		return nil, err
	}
	setupContent, err := RenderTemplate("proxy-setup", proxySetupTemplate, c)
	if err != nil {
		return nil, err
	}

	templates := []struct{ name, tmpl string }{
		{"write-file-proxy-profile", writeFileProxyProfileTmpl},
		{"write-file-proxy-env", writeFileProxyEnvTmpl},
		{"write-file-proxy-setup", writeFileProxySetupTmpl},
	}
	contents := []string{profileContent, envFileContent, setupContent}

	result := make([]string, 0, len(templates))
	for i, t := range templates {
		rendered, err := RenderTemplate(t.name, t.tmpl, writeFileData{
			Content: IndentLines(contents[i]),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, strings.TrimRight(rendered, "\n"))
	}
	return result, nil
}

// renderWriteFiles renders a list of write_files templates with the given data.
func renderWriteFiles(templates []struct{ name, tmpl string }, data writeFileData) ([]string, error) {
	result := make([]string, 0, len(templates))
	for _, t := range templates {
		rendered, err := RenderTemplate(t.name, t.tmpl, data)
		if err != nil {
			return nil, err
		}
		result = append(result, strings.TrimRight(rendered, "\n"))
	}
	return result, nil
}
