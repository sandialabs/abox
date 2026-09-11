// Package netroute provides a best-effort, fail-open probe of the host routing
// table, used by subnet allocation to avoid handing out a /24 the host already
// routes elsewhere (e.g. a VPN's split-include route, the host's own LAN, or a
// leftover bridge route). It shells out to the platform route tool with a bounded
// timeout; any error resolves to "not routed" so a flaky probe never blocks
// allocation. On platforms without a supported prober it is a no-op.
package netroute
