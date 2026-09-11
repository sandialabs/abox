//go:build darwin

package filterbase

// DNSListenAddress returns the address the DNS filter binds to. On macOS the
// pfctl rdr rule redirects guest DNS to 127.0.0.1:<dnsPort>, so the filter must
// listen on loopback rather than the gateway.
func DNSListenAddress(_ string) string { return loopbackAddr }

// HTTPListenAddress returns the address the HTTP proxy binds to. There is no pf
// rdr for HTTP — the guest is pointed at the gateway directly by cloud-init, and
// the anchor's "pass quick proto tcp from <subnet> to <gateway> port <httpPort>"
// is what admits it. The gateway address belongs to the vmnet bridge, which does
// not exist yet when the filters start (the DNS port has to be known before the
// pre-boot anchor loads), so binding it would fail with EADDRNOTAVAIL. Bind the
// wildcard instead and let pf gate reachability.
func HTTPListenAddress(_ string) string { return "0.0.0.0" }
