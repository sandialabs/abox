package doctor

import (
	"fmt"
	"os"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/dnsfilter"
	"github.com/sandialabs/abox/internal/httpfilter"
	"github.com/sandialabs/abox/internal/rpc"
)

// filterChecker checks a filter service and returns a CheckResult.
type filterChecker struct {
	filterName string
	socketPath string
	port       int
	instName   string
	dial       func() (filterClient, func(), error) // returns client, cleanup func, error
}

// filterClient is the minimal interface for filter status checking.
type filterClient interface {
	GetMode() string
	Close() error
}

type dnsClientWrapper struct {
	client *dnsfilter.Client
	mode   string
}

func (w *dnsClientWrapper) GetMode() string { return w.mode }
func (w *dnsClientWrapper) Close() error    { return w.client.Close() }

type httpClientWrapper struct {
	client *httpfilter.Client
	mode   string
}

func (w *httpClientWrapper) GetMode() string { return w.mode }
func (w *httpClientWrapper) Close() error    { return w.client.Close() }

func (c *filterChecker) check() CheckResult {
	result := CheckResult{Name: c.filterName + " filter running"}

	// Check if socket exists
	if _, err := os.Stat(c.socketPath); os.IsNotExist(err) {
		result.Passed = false
		result.Details = "socket not found: " + c.socketPath
		result.Hint = fmt.Sprintf("Try 'abox start %s' to restart filters", c.instName)
		return result
	}

	// Try to connect and get status
	client, cleanup, err := c.dial()
	if err != nil {
		result.Passed = false
		result.Details = fmt.Sprintf("cannot connect: %s", err)
		result.Hint = fmt.Sprintf("Try 'abox start %s' to restart filters", c.instName)
		return result
	}
	defer cleanup()

	// Note: We already called Status inside the dial func to get the mode
	result.Passed = true
	result.Details = fmt.Sprintf("mode: %s, port: %d", client.GetMode(), c.port)
	return result
}

// checkDNSFilterGeneric checks the DNS filter using the generic checker.
func checkDNSFilterGeneric(name string, paths *config.Paths, port int) CheckResult {
	checker := &filterChecker{
		filterName: "DNS",
		socketPath: paths.DNSSocket,
		port:       port,
		instName:   name,
		dial: func() (filterClient, func(), error) {
			client, err := dnsfilter.Dial(paths.DNSSocket)
			if err != nil {
				return nil, nil, err
			}
			ctx, cancel := dnsfilter.ClientContext()
			status, err := client.Client().Status(ctx, &rpc.Empty{})
			if err != nil {
				cancel()
				_ = client.Close()
				return nil, nil, err
			}
			cleanup := func() {
				cancel()
				_ = client.Close()
			}
			return &dnsClientWrapper{client: client, mode: status.Mode}, cleanup, nil
		},
	}
	return checker.check()
}

// checkHTTPFilterGeneric checks the HTTP filter using the generic checker.
func checkHTTPFilterGeneric(name string, paths *config.Paths, port int) CheckResult {
	checker := &filterChecker{
		filterName: "HTTP",
		socketPath: paths.HTTPSocket,
		port:       port,
		instName:   name,
		dial: func() (filterClient, func(), error) {
			client, err := httpfilter.Dial(paths.HTTPSocket)
			if err != nil {
				return nil, nil, err
			}
			ctx, cancel := httpfilter.ClientContext()
			status, err := client.Client().Status(ctx, &rpc.Empty{})
			if err != nil {
				cancel()
				_ = client.Close()
				return nil, nil, err
			}
			cleanup := func() {
				cancel()
				_ = client.Close()
			}
			return &httpClientWrapper{client: client, mode: status.Mode}, cleanup, nil
		},
	}
	return checker.check()
}

// CountResults tallies passed/failed/skipped counts from a slice of check results.
func CountResults(results []CheckResult) (passed, failed, skipped int) {
	for _, r := range results {
		switch {
		case r.Skipped:
			skipped++
		case r.Passed:
			passed++
		default:
			failed++
		}
	}
	return
}

// CheckID identifies a check for diagram mapping.
type CheckID string

const (
	CheckConfig       CheckID = "config"
	CheckVM           CheckID = "vm"
	CheckBridge       CheckID = "bridge"
	CheckVMIP         CheckID = "vmip"
	CheckHostDisk     CheckID = "hostdisk"
	CheckDNSFilter    CheckID = "dnsfilter"
	CheckHTTPFilter   CheckID = "httpfilter"
	CheckDNSUpstream  CheckID = "dnsupstream"
	CheckSSH          CheckID = "ssh"
	CheckGateway      CheckID = "gateway"
	CheckDNSResolve   CheckID = "dnsresolve"
	CheckHTTPProxy    CheckID = "httpproxy"
	CheckGuestDisk    CheckID = "guestdisk"
	CheckProxyEnv     CheckID = "proxyenv"
	CheckDNSConfig    CheckID = "dnsconfig"
	CheckHTTPUpstream CheckID = "httpupstream"
)

// User-visible check names. These appear in CLI output and TUI.
const (
	CheckNameConfig       = "Instance configuration valid"
	CheckNameVMRunning    = "VM running"
	CheckNameBridge       = "Network bridge active"
	CheckNameVMIP         = "VM IP address"
	CheckNameHostDisk     = "Host disk space"
	CheckNameDNSFilter    = "DNS filter running"
	CheckNameHTTPFilter   = "HTTP filter running"
	CheckNameDNSUpstream  = "DNS upstream reachable"
	CheckNameSSH          = "SSH connection"
	CheckNameGateway      = "Gateway reachable"
	CheckNameDNSResolve   = "DNS resolution working"
	CheckNameHTTPProxy    = "HTTP proxy reachable"
	CheckNameGuestDisk    = "Guest disk space"
	CheckNameProxyEnv     = "Proxy environment variables"
	CheckNameDNSConfig    = "DNS configuration"
	CheckNameHTTPUpstream = "HTTP upstream reachable"
)

// checkNameToID maps result names to check IDs.
var checkNameToID = map[string]CheckID{
	CheckNameConfig:       CheckConfig,
	CheckNameVMRunning:    CheckVM,
	CheckNameBridge:       CheckBridge,
	CheckNameVMIP:         CheckVMIP,
	CheckNameHostDisk:     CheckHostDisk,
	CheckNameDNSFilter:    CheckDNSFilter,
	CheckNameHTTPFilter:   CheckHTTPFilter,
	CheckNameDNSUpstream:  CheckDNSUpstream,
	CheckNameSSH:          CheckSSH,
	CheckNameGateway:      CheckGateway,
	CheckNameDNSResolve:   CheckDNSResolve,
	CheckNameHTTPProxy:    CheckHTTPProxy,
	CheckNameGuestDisk:    CheckGuestDisk,
	CheckNameProxyEnv:     CheckProxyEnv,
	CheckNameDNSConfig:    CheckDNSConfig,
	CheckNameHTTPUpstream: CheckHTTPUpstream,
}

// CheckIDFromName returns the CheckID for a given check result name.
func CheckIDFromName(name string) (CheckID, bool) {
	id, ok := checkNameToID[name]
	return id, ok
}
