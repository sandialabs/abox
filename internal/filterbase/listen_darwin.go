//go:build darwin

package filterbase

// DNSListenAddress returns the address the DNS filter should bind to.
// On macOS, we bind to localhost because pfctl redirects VM DNS traffic
// to this address. The VM never connects here directly.
func DNSListenAddress(_ string) string {
	return "127.0.0.1"
}

// HTTPListenAddress returns the address the HTTP filter should bind to.
// On macOS, we bind to all interfaces so the VM can reach the proxy
// at the vmnet gateway IP. There is no pfctl redirect for HTTP — the VM
// is configured via cloud-init to connect to the proxy directly.
func HTTPListenAddress(_ string) string {
	return "0.0.0.0"
}
