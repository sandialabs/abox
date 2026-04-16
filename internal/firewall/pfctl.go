//go:build darwin

package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// PfctlClient manages macOS PF firewall rules for DNS traffic redirection
// via the privilege helper RPC. Each instance gets its own PF anchor (abox/<name>).
type PfctlClient struct {
	priv rpc.PrivilegeClient
}

// NewPfctlClient creates a new PF client from a privilege client.
func NewPfctlClient(priv rpc.PrivilegeClient) *PfctlClient {
	return &PfctlClient{priv: priv}
}

// EnsureEnabled enables the PF firewall if not already active.
func (c *PfctlClient) EnsureEnabled() error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err := c.priv.PfctlEnable(ctx, &rpc.Empty{})
	if err != nil {
		return fmt.Errorf("failed to enable PF: %w", err)
	}
	return nil
}

// AddDNSRedirect adds PF rules to redirect DNS traffic from a VM to the dnsfilter.
// Rules are loaded into the abox/<name> anchor so they don't conflict with other instances.
func (c *PfctlClient) AddDNSRedirect(name string, vmIP string, dnsPort int) error {
	if err := validatePfctlArgs(name, vmIP, dnsPort); err != nil {
		return err
	}

	logging.Debug("adding PF DNS redirect rules", "instance", name, "vm_ip", vmIP, "dns_port", dnsPort)

	rules := buildDNSRedirectRules(vmIP, dnsPort)

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err := c.priv.PfctlLoadAnchor(ctx, &rpc.PfctlAnchorReq{
		InstanceName: name,
		RulesContent: rules,
	})
	if err != nil {
		return fmt.Errorf("failed to load PF rules: %w", err)
	}

	logging.Audit("PF DNS redirect added",
		"action", logging.ActionPfctlAddDNS,
		"instance", name,
		"vm_ip", vmIP,
		"dns_port", dnsPort,
	)

	return nil
}

// Flush removes all PF rules from the instance's anchor.
// This is best-effort — errors are logged but do not cause failure.
func (c *PfctlClient) Flush(name string) {
	logging.Debug("flushing PF rules", "instance", name)

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	if _, err := c.priv.PfctlFlushAnchor(ctx, &rpc.PfctlAnchorReq{
		InstanceName: name,
	}); err != nil {
		logging.Debug("failed to flush PF rules", "instance", name, "error", err)
	}

	logging.Audit("PF DNS redirect flushed",
		"action", logging.ActionPfctlFlushDNS,
		"instance", name,
	)
}

// buildDNSRedirectRules generates PF rules for DNS traffic redirection.
func buildDNSRedirectRules(vmIP string, dnsPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# abox DNS redirect rules\n")
	fmt.Fprintf(&b, "rdr pass proto udp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	fmt.Fprintf(&b, "rdr pass proto tcp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	return b.String()
}

// validatePfctlArgs validates the inputs for PF rule creation.
func validatePfctlArgs(name string, vmIP string, dnsPort int) error {
	if name == "" {
		return errors.New("instance name is required")
	}
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' {
			return fmt.Errorf("invalid instance name %q: contains unsafe character %q", name, c)
		}
	}

	ip := net.ParseIP(vmIP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid VM IP address %q", vmIP)
	}

	if dnsPort < 1024 || dnsPort > 65535 {
		return fmt.Errorf("invalid DNS port %d: must be 1024-65535", dnsPort)
	}

	return nil
}
