// Package firewall provides clients for managing host-level firewall rules
// (iptables and UFW) via the privilege helper.
package firewall

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// IPTablesClient wraps the privilege client for iptables operations.
type IPTablesClient struct {
	priv rpc.PrivilegeClient
}

// NewIPTablesClient creates a new iptables client from a privilege client.
func NewIPTablesClient(priv rpc.PrivilegeClient) *IPTablesClient {
	return &IPTablesClient{priv: priv}
}

// AddDNSRedirect adds iptables NAT rules to redirect DNS traffic to dnsfilter.
// It first flushes any existing DNS redirect rules for this bridge to avoid
// stale rules from previous runs (e.g., when dnsfilter got a different port).
// Returns error if any rule fails to add.
func (c *IPTablesClient) AddDNSRedirect(inst *config.Instance) error {
	logging.Debug("adding DNS redirect rules", "bridge", inst.Bridge, "dns_port", inst.DNS.Port)

	// First, flush any existing rules for this bridge
	c.Flush(inst.Bridge)

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	// Add UDP rule
	_, err := c.priv.IptablesAdd(ctx, &rpc.IptablesReq{
		Bridge:   inst.Bridge,
		DnsPort:  int32(inst.DNS.Port), //nolint:gosec // port is 0-65535, fits int32
		Protocol: "udp",
	})
	if err != nil {
		return fmt.Errorf("failed to add UDP iptables rule: %w", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel2()

	// Add TCP rule
	_, err = c.priv.IptablesAdd(ctx2, &rpc.IptablesReq{
		Bridge:   inst.Bridge,
		DnsPort:  int32(inst.DNS.Port), //nolint:gosec // port is 0-65535, fits int32
		Protocol: "tcp",
	})
	if err != nil {
		// Rollback: remove the UDP rule we just added
		c.removeRule(inst.Bridge, inst.DNS.Port, "udp")
		return fmt.Errorf("failed to add TCP iptables rule (UDP rule rolled back): %w", err)
	}

	logging.Audit("iptables DNS redirect added",
		"action", logging.ActionIptablesAddDNS,
		"bridge", inst.Bridge,
		"dns_port", inst.DNS.Port,
	)

	return nil
}

// Flush removes ALL DNS redirect rules for a bridge, regardless of port.
// This is used to clean up stale rules from previous runs.
func (c *IPTablesClient) Flush(bridge string) {
	logging.Debug("flushing iptables DNS redirect rules", "bridge", bridge)

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()
	if _, err := c.priv.IptablesFlush(ctx, &rpc.IptablesFlushReq{
		Bridge: bridge,
	}); err != nil {
		logging.Debug("failed to flush iptables rules", "bridge", bridge, "error", err)
	}
	logging.Audit("iptables DNS redirect flushed",
		"action", logging.ActionIptablesFlushDNS,
		"bridge", bridge,
	)
}

func (c *IPTablesClient) removeRule(bridge string, port int, protocol string) {
	logging.Debug("removing iptables rule", "bridge", bridge, "port", port, "protocol", protocol)

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()
	if _, err := c.priv.IptablesRemove(ctx, &rpc.IptablesReq{
		Bridge:   bridge,
		DnsPort:  int32(port), //nolint:gosec // port is 0-65535
		Protocol: protocol,
	}); err != nil {
		logging.Debug("failed to remove iptables rule", "bridge", bridge, "port", port, "protocol", protocol, "error", err)
	}
}
