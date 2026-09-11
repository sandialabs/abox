//go:build linux

package filterbase

// DNSListenAddress returns the address the DNS filter binds to. On Linux the
// iptables REDIRECT target is the bridge/gateway IP, so the filter listens on the
// gateway.
func DNSListenAddress(gateway string) string { return gateway }

// HTTPListenAddress returns the address the HTTP proxy binds to. On Linux the
// bridge exists before the filters start, so the proxy binds the gateway IP the
// guest is pointed at via cloud-init — no other host interface is exposed.
func HTTPListenAddress(gateway string) string { return gateway }
