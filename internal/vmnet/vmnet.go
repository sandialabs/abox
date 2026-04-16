//go:build darwin

// Package vmnet detects macOS vmnet shared mode networking parameters.
// vmnet.framework provides NAT networking for VMs; the host acts as the
// gateway at the first IP in the vmnet subnet (typically 192.168.64.1).
package vmnet

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// Default vmnet shared mode values. macOS allocates 192.168.64.0/24
// for vmnet shared mode unless overridden via
// /Library/Preferences/SystemConfiguration/com.apple.vmnet.plist.
const (
	DefaultGateway = "192.168.64.1"
	DefaultSubnet  = "192.168.64.0/24"
)

// ifconfigBridge matches "inet X.X.X.X" lines in ifconfig output for bridge interfaces.
var ifconfigInet = regexp.MustCompile(`inet\s+(\d+\.\d+\.\d+\.\d+)`)

// GatewayIP detects the vmnet shared mode gateway IP by looking for
// bridge interfaces with IPs in the vmnet range. Falls back to DefaultGateway
// if detection fails.
func GatewayIP() string {
	gw, err := detectGateway(runIfconfig)
	if err != nil {
		return DefaultGateway
	}
	return gw
}

// Subnet returns the vmnet subnet in CIDR notation corresponding to
// the detected gateway IP.
func Subnet() string {
	gw := GatewayIP()
	ip := net.ParseIP(gw)
	if ip == nil {
		return DefaultSubnet
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return DefaultSubnet
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
}

// runIfconfig executes "ifconfig" and returns the output.
func runIfconfig() (string, error) {
	out, err := exec.Command("ifconfig").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run ifconfig: %w", err)
	}
	return string(out), nil
}

// detectGateway parses ifconfig output to find the vmnet bridge gateway.
// It looks for bridge interfaces whose IP ends in .1 and falls within
// a private subnet range commonly used by vmnet (192.168.64.0/24 etc.).
func detectGateway(ifconfigFn func() (string, error)) (string, error) {
	output, err := ifconfigFn()
	if err != nil {
		return "", err
	}

	return parseGatewayFromIfconfig(output)
}

// parseGatewayFromIfconfig extracts the vmnet gateway IP from ifconfig output.
// It searches for bridge interfaces with an IP ending in .1 in the 192.168.x.x range,
// which is the standard vmnet shared mode address space.
func parseGatewayFromIfconfig(output string) (string, error) {
	// Split into interface blocks — each starts at a line that doesn't begin with whitespace
	blocks := splitInterfaceBlocks(output)

	for _, block := range blocks {
		// Only consider bridge interfaces
		if !strings.HasPrefix(block, "bridge") {
			continue
		}

		// Look for inet addresses in this block
		matches := ifconfigInet.FindAllStringSubmatch(block, -1)
		for _, m := range matches {
			ip := m[1]
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			ip4 := parsed.To4()
			if ip4 == nil {
				continue
			}
			// Check for vmnet pattern: 192.168.x.1
			if ip4[0] == 192 && ip4[1] == 168 && ip4[3] == 1 {
				return ip, nil
			}
		}
	}

	return "", errors.New("no vmnet bridge interface found")
}

// splitInterfaceBlocks splits ifconfig output into per-interface blocks.
// Each block starts with a non-whitespace line (the interface header).
func splitInterfaceBlocks(output string) []string {
	var blocks []string
	var current strings.Builder

	for line := range strings.SplitSeq(output, "\n") {
		if len(line) > 0 && line[0] != '\t' && line[0] != ' ' {
			// Start of a new interface block
			if current.Len() > 0 {
				blocks = append(blocks, current.String())
				current.Reset()
			}
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	if current.Len() > 0 {
		blocks = append(blocks, current.String())
	}

	return blocks
}
