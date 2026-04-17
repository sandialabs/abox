//go:build darwin

package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// PfctlClient manages macOS PF firewall rules for per-instance traffic
// interception via the privilege helper RPC. Each instance gets its own
// PF anchor (abox/<name>) containing DNS redirect rules and a default-deny
// outbound policy with explicit allows for the proxy, DHCP, and ICMP to the
// gateway.
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

// ApplyInstanceRules installs the full per-instance rule set into abox/<name>:
// DNS redirect + default-deny outbound with explicit allows for DHCP, the HTTP
// proxy on the gateway, and ICMP to the gateway. Writes a marker file so
// TrafficInterceptor.FilterExists can report accurate state without needing
// its own privilege client.
func (c *PfctlClient) ApplyInstanceRules(name, vmIP, gateway string, dnsPort, httpPort int) error {
	if err := validatePfctlArgs(name, vmIP, gateway, dnsPort, httpPort); err != nil {
		return err
	}

	logging.Debug("applying PF instance rules",
		"instance", name, "vm_ip", vmIP, "gateway", gateway,
		"dns_port", dnsPort, "http_port", httpPort)

	rules := buildInstanceRules(vmIP, gateway, dnsPort, httpPort)

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err := c.priv.PfctlLoadAnchor(ctx, &rpc.PfctlAnchorReq{
		InstanceName: name,
		RulesContent: rules,
	})
	if err != nil {
		return fmt.Errorf("failed to load PF rules: %w", err)
	}

	if err := writeFilterMarker(filterName(name)); err != nil {
		logging.Debug("failed to write filter marker", "instance", name, "error", err)
	}

	logging.Audit("PF instance rules applied",
		"action", logging.ActionPfctlAddDNS,
		"instance", name,
		"vm_ip", vmIP,
		"dns_port", dnsPort,
		"http_port", httpPort,
	)

	return nil
}

// Flush removes all PF rules from the instance's anchor and clears the
// filter marker file. Best-effort — errors are logged but do not cause failure.
func (c *PfctlClient) Flush(name string) {
	logging.Debug("flushing PF rules", "instance", name)

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	if _, err := c.priv.PfctlFlushAnchor(ctx, &rpc.PfctlAnchorReq{
		InstanceName: name,
	}); err != nil {
		logging.Debug("failed to flush PF rules", "instance", name, "error", err)
	}

	if err := removeFilterMarker(filterName(name)); err != nil {
		logging.Debug("failed to remove filter marker", "instance", name, "error", err)
	}

	logging.Audit("PF instance rules flushed",
		"action", logging.ActionPfctlFlushDNS,
		"instance", name,
	)
}

// buildInstanceRules generates the PF ruleset for a single instance:
//   - rdr rules redirect VM DNS traffic (any :53) to 127.0.0.1:<dnsPort>
//   - pass rules allow DHCP, HTTP proxy on the gateway, and ICMP to the gateway
//   - a terminal "block drop quick" drops everything else from the VM
//
// Rules are anchored by source IP rather than interface so they don't need
// vmnet bridge name detection (bridge100/bridge101/...).
func buildInstanceRules(vmIP, gateway string, dnsPort, httpPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# abox instance traffic rules for %s\n", vmIP)
	fmt.Fprintf(&b, "# DNS redirect (VM queries to any :53 -> local dnsfilter)\n")
	fmt.Fprintf(&b, "rdr pass proto udp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	fmt.Fprintf(&b, "rdr pass proto tcp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	fmt.Fprintf(&b, "# Allowlisted outbound\n")
	fmt.Fprintf(&b, "pass quick proto udp from %s port 68 to any port 67\n", vmIP)
	fmt.Fprintf(&b, "pass quick proto tcp from %s to %s port %d\n", vmIP, gateway, httpPort)
	fmt.Fprintf(&b, "pass quick proto icmp from %s to %s\n", vmIP, gateway)
	fmt.Fprintf(&b, "# Default deny: everything else from the VM is dropped\n")
	fmt.Fprintf(&b, "block drop quick from %s to any\n", vmIP)
	return b.String()
}

// validatePfctlArgs validates the inputs for PF rule creation.
func validatePfctlArgs(name, vmIP, gateway string, dnsPort, httpPort int) error {
	if name == "" {
		return errors.New("instance name is required")
	}
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' {
			return fmt.Errorf("invalid instance name %q: contains unsafe character %q", name, c)
		}
	}

	if ip := net.ParseIP(vmIP); ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid VM IP address %q", vmIP)
	}
	if ip := net.ParseIP(gateway); ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid gateway IP address %q", gateway)
	}

	if dnsPort < 1024 || dnsPort > 65535 {
		return fmt.Errorf("invalid DNS port %d: must be 1024-65535", dnsPort)
	}
	if httpPort < 1024 || httpPort > 65535 {
		return fmt.Errorf("invalid HTTP port %d: must be 1024-65535", httpPort)
	}

	return nil
}

// filterName returns the backend-resource filter name for an instance.
// Kept in sync with darwin backend ResourceNames.
func filterName(instance string) string {
	return "abox-" + instance + "-traffic"
}

// filterMarkerPath returns the path to the per-filter state marker. The marker
// records that ApplyInstanceRules loaded rules into the anchor. It lets
// TrafficInterceptor.FilterExists answer without its own privilege client.
func filterMarkerPath(filter string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Caches", "abox", "filters", filter+".applied"), nil
}

func writeFilterMarker(filter string) error {
	path, err := filterMarkerPath(filter)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, nil, 0o600)
}

func removeFilterMarker(filter string) error {
	path, err := filterMarkerPath(filter)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// FilterMarkerExists reports whether the per-filter state marker is present.
// This is the source of truth for TrafficInterceptor.FilterExists on darwin.
func FilterMarkerExists(filter string) bool {
	path, err := filterMarkerPath(filter)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}
