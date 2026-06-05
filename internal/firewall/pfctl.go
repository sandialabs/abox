//go:build darwin

package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// bridgeNameRE matches vmnet bridge interface names (bridge100, bridge101, …).
// The bridge name is interpolated into a pfctl ruleset, so it must be strictly
// validated to prevent rule injection.
var bridgeNameRE = regexp.MustCompile(`^bridge[0-9]+$`)

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

// EnsureEnabled wires abox anchor references into /etc/pf.conf if they're not
// already present (running `pfctl -f /etc/pf.conf` once to reload the main
// ruleset) and then enables the PF firewall. Both operations are idempotent:
// already-wired pf.conf is a no-op, and `pfctl -e` on an already-enabled PF
// is treated as success.
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
func (c *PfctlClient) ApplyInstanceRules(name, vmIP, gateway, bridge string, dnsPort, httpPort int) error {
	if err := validatePfctlArgs(name, vmIP, gateway, bridge, dnsPort, httpPort); err != nil {
		return err
	}

	logging.Debug("applying PF instance rules",
		"instance", name, "vm_ip", vmIP, "gateway", gateway, "bridge", bridge,
		"dns_port", dnsPort, "http_port", httpPort)

	rules := buildInstanceRules(vmIP, gateway, bridge, dnsPort, httpPort)

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

// TeardownConfig removes the abox-managed anchor references from /etc/pf.conf
// and reloads the main ruleset. Returns an error if the helper fails to update
// the file or if the reload fails. Used by `abox teardown-pf`.
func (c *PfctlClient) TeardownConfig() error {
	logging.Debug("tearing down PF anchor references in /etc/pf.conf")

	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()

	_, err := c.priv.PfctlTeardownConfig(ctx, &rpc.Empty{})
	if err != nil {
		return fmt.Errorf("failed to tear down PF config: %w", err)
	}

	logging.Audit("PF anchor references removed from /etc/pf.conf",
		"action", logging.ActionPfctlUnwireAnchors,
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
//   - an inet6 block on the VM's bridge kills all IPv6 (vmnet has no flag to
//     disable NAT66/link-local v6, which would otherwise leak past the
//     IPv4-only default-deny rule)
//   - a terminal "block drop quick" drops everything else from the VM
//
// IPv4 rules are anchored by source IP rather than interface so they don't need
// vmnet bridge name detection. The IPv6 block is scoped to the per-VM bridge so
// it only affects this instance, never the host or other VMs.
func buildInstanceRules(vmIP, gateway, bridge string, dnsPort, httpPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# abox instance traffic rules for %s\n", vmIP)
	fmt.Fprintf(&b, "# DNS redirect (VM queries to any :53 -> local dnsfilter)\n")
	fmt.Fprintf(&b, "rdr pass proto udp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	fmt.Fprintf(&b, "rdr pass proto tcp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	fmt.Fprintf(&b, "# Block all IPv6 on this VM's bridge (vmnet has no flag to disable NAT66)\n")
	fmt.Fprintf(&b, "block drop quick on %s inet6 all\n", bridge)
	fmt.Fprintf(&b, "# Allowlisted outbound\n")
	fmt.Fprintf(&b, "pass quick proto udp from %s port 68 to any port 67\n", vmIP)
	fmt.Fprintf(&b, "pass quick proto tcp from %s to %s port %d\n", vmIP, gateway, httpPort)
	fmt.Fprintf(&b, "pass quick proto icmp from %s to %s\n", vmIP, gateway)
	fmt.Fprintf(&b, "# Default deny: everything else from the VM is dropped\n")
	fmt.Fprintf(&b, "block drop quick from %s to any\n", vmIP)
	return b.String()
}

// validatePfctlArgs validates the inputs for PF rule creation.
func validatePfctlArgs(name, vmIP, gateway, bridge string, dnsPort, httpPort int) error {
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
	if !bridgeNameRE.MatchString(bridge) {
		return fmt.Errorf("invalid bridge interface %q: must match bridge[0-9]+", bridge)
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
