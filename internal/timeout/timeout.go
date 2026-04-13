// Package timeout provides shared timeout constants for privileged operations.
package timeout

import "time"

const (
	// Default is the timeout for privileged operations (virsh, iptables, etc.)
	Default = 30 * time.Second

	// DNSClient is the timeout for DNS filter client operations
	DNSClient = 5 * time.Second

	// HTTPClient is the timeout for HTTP filter client operations
	HTTPClient = 5 * time.Second

	// MonitorClient is the timeout for monitor daemon client operations
	MonitorClient = 5 * time.Second
)
