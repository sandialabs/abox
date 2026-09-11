// Package pfvalidate holds the pure, dependency-free validation primitives that
// the macOS pf egress code validates on BOTH sides of the trust boundary: the
// unprivileged client (internal/firewall) that builds the ruleset, and the
// privileged helper (internal/privilege) that independently re-validates it
// before loading it into a root anchor.
//
// The two sides deliberately each call these primitives on their own inputs —
// client-side validation is not a trust boundary, so the helper must not depend
// on it. Housing the shared checks here keeps a single source of truth (the
// compiler now enforces the agreement the old "keep in sync" comments asked for)
// WITHOUT weakening the client-re-validates-server model.
//
// This package is a leaf: it imports only the standard library and must never
// import internal/firewall, internal/privilege, or anything that would grow the
// setuid helper's dependency/trust surface.
package pfvalidate

import (
	"errors"
	"fmt"
	"net"
	"regexp"
)

// BridgeNameRE matches the VM bridge interface names abox drives on macOS:
// vfkit's bridgeN interfaces (bridge100, bridge101, …) and VMware Fusion's
// vmnetN interfaces (vmnet2, vmnet19, …). A bridge name is interpolated into a
// pf ruleset, so it must be strictly validated to prevent rule injection.
var BridgeNameRE = regexp.MustCompile(`^(bridge|vmnet)[0-9]+$`)

// MatchBridgeName reports whether s is an accepted VM bridge interface name.
func MatchBridgeName(s string) bool {
	return BridgeNameRE.MatchString(s)
}

// ValidatePort reports whether port is in the unprivileged 1024-65535 range used
// for the per-instance dnsfilter/httpfilter ports.
func ValidatePort(port int) bool {
	return port >= 1024 && port <= 65535
}

// ValidateInstanceName enforces the anchor-safe instance-name rule shared by the
// pf client and helper: non-empty, first character an ASCII letter or digit (so
// the name can never be mistaken for a pfctl flag), and every character an ASCII
// letter, digit, or '-'.
//
// This intentionally differs from internal/validation.ValidateInstanceName,
// which requires a leading letter and permits '_': pf anchor names allow a
// leading digit and forbid '_'. Any maximum-length policy is a caller concern
// and is enforced by the caller, not here.
func ValidateInstanceName(name string) error {
	if name == "" {
		return errors.New("instance name is required")
	}
	if c := name[0]; !isNameChar(c) {
		return fmt.Errorf("invalid instance name %q: must start with a letter or digit", name)
	}
	// Iterate bytes (not runes): valid names are ASCII, so any byte >= 0x80 is
	// rejected here as an unsafe character.
	for i := range len(name) {
		if c := name[i]; !isNameChar(c) && c != '-' {
			return fmt.Errorf("invalid instance name %q: contains unsafe character %q", name, rune(c))
		}
	}
	return nil
}

// isNameChar reports whether c is an ASCII letter or digit.
func isNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// ParseSubnet24 validates that subnet is an IPv4 /24 CIDR written as its network
// address and returns the canonical network and its .1 gateway host.
//
// It is the single place the subnet binding is derived, so the client generator
// and the server validator agree: the client additionally checks a
// caller-supplied gateway equals the returned one, while the helper uses the
// returned network/gateway as the tokens every rule line is bound to.
func ParseSubnet24(subnet string) (network net.IPNet, gateway net.IP, err error) {
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return net.IPNet{}, nil, fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return net.IPNet{}, nil, fmt.Errorf("subnet %q is not IPv4", subnet)
	}
	if ones, bits := ipnet.Mask.Size(); ones != 24 || bits != 32 {
		return net.IPNet{}, nil, fmt.Errorf("subnet %q must be a /24", subnet)
	}
	// Canonicalize to the network address (reject e.g. 10.0.0.5/24 in place of
	// 10.0.0.0/24 so the derived tokens are deterministic).
	net4 := ipnet.IP.To4()
	if !net4.Equal(ip4) {
		return net.IPNet{}, nil, fmt.Errorf("subnet %q must be the network address (%s)", subnet, ipnet.String())
	}
	gw := make(net.IP, len(net4))
	copy(gw, net4)
	gw[3] = 1
	return net.IPNet{IP: net4, Mask: ipnet.Mask}, gw, nil
}
