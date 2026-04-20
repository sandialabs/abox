//go:build darwin

package vmnethelper

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// bridgeScanInterval and bridgeScanAttempts bound the retry loop that
// waits for a new vmnet bridge to appear in ifconfig after vmnet-helper
// emits its start JSON.
const (
	bridgeScanInterval = 50 * time.Millisecond
	bridgeScanAttempts = 20 // 50ms × 20 = 1s total
)

// ifconfigInet matches "inet X.X.X.X" lines in ifconfig output.
var ifconfigInet = regexp.MustCompile(`inet\s+(\d+\.\d+\.\d+\.\d+)`)

// runIfconfig is a var so tests can inject canned output.
var runIfconfig = func() (string, error) {
	out, err := exec.Command("ifconfig").Output()
	if err != nil {
		return "", fmt.Errorf("run ifconfig: %w", err)
	}
	return string(out), nil
}

// sleepFn is injectable for tests.
var sleepFn = time.Sleep

// BridgeInterfaceForGateway scans `ifconfig` output for a bridge
// interface whose inet equals gatewayIP. Retries every 50ms up to 1s
// to cover the race between vmnet-helper emitting its start JSON and
// the new bridge appearing in the kernel's interface list.
func BridgeInterfaceForGateway(gatewayIP string) (string, error) {
	if gatewayIP == "" {
		return "", errors.New("gateway IP is empty")
	}
	var lastErr error
	for attempt := range bridgeScanAttempts {
		output, err := runIfconfig()
		if err != nil {
			lastErr = err
		} else {
			iface, err := parseBridgeFromIfconfig(output, gatewayIP)
			if err == nil {
				return iface, nil
			}
			lastErr = err
		}
		if attempt < bridgeScanAttempts-1 {
			sleepFn(bridgeScanInterval)
		}
	}
	return "", fmt.Errorf("resolve bridge for gateway %s: %w", gatewayIP, lastErr)
}

// parseBridgeFromIfconfig returns the interface name of the first
// bridge block in output whose inet matches gatewayIP. Returns an
// error if no match is found.
func parseBridgeFromIfconfig(output, gatewayIP string) (string, error) {
	want := net.ParseIP(gatewayIP)
	if want == nil {
		return "", fmt.Errorf("invalid gateway IP %q", gatewayIP)
	}

	for _, block := range splitInterfaceBlocks(output) {
		name := interfaceName(block)
		if !strings.HasPrefix(name, "bridge") {
			continue
		}
		for _, m := range ifconfigInet.FindAllStringSubmatch(block, -1) {
			got := net.ParseIP(m[1])
			if got == nil {
				continue
			}
			if got.Equal(want) {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("no bridge interface with inet %s", gatewayIP)
}

// interfaceName extracts the interface name from a block header line
// like "bridge101: flags=…". Returns empty string if the block has no
// header.
func interfaceName(block string) string {
	line, _, _ := strings.Cut(block, "\n")
	name, _, found := strings.Cut(line, ":")
	if !found {
		return ""
	}
	return strings.TrimSpace(name)
}

// splitInterfaceBlocks splits ifconfig output into per-interface blocks.
// Each block starts with a non-whitespace line (the interface header).
func splitInterfaceBlocks(output string) []string {
	var blocks []string
	var current strings.Builder

	for line := range strings.SplitSeq(output, "\n") {
		if len(line) > 0 && line[0] != '\t' && line[0] != ' ' {
			// Start of a new interface block.
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
