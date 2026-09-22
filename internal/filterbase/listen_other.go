//go:build !linux && !darwin

package filterbase

// DNSListenAddress returns the address the DNS filter binds to. On platforms
// without a dedicated redirect mechanism, fall back to the gateway (matching
// Linux) so the package still compiles and behaves sensibly.
func DNSListenAddress(gateway string) string { return gateway }

// HTTPListenAddress returns the address the HTTP proxy binds to. Same fallback
// reasoning as DNSListenAddress: bind the gateway, matching Linux.
func HTTPListenAddress(gateway string) string { return gateway }
