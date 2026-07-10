//go:build linux

package filterbase

// DNSListenAddress returns the address the DNS filter should bind to.
// On Linux, this is the bridge gateway IP because iptables REDIRECT
// sends packets to the bridge interface address.
func DNSListenAddress(gateway string) string {
	return gateway
}

// HTTPListenAddress returns the address the HTTP filter should bind to.
// On Linux, this is the bridge gateway IP — the VM is configured via
// cloud-init to use the gateway as its HTTP proxy.
func HTTPListenAddress(gateway string) string {
	return gateway
}
