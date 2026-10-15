// Package netroute provides a best-effort, fail-open probe of the host routing
// table, used by subnet allocation to avoid handing out a /24 the host already
// routes elsewhere (e.g. a VPN's split-include route, the host's own LAN, or a
// leftover bridge route). Only covering routes at /24 or narrower count:
// broader routes (default, a full-tunnel VPN's 0.0.0.0/1 halves, a /16
// split-include) lose longest-prefix match to the connected /24 and are
// ignored. It shells out to the platform route tool with a bounded timeout;
// any error resolves to "not routed" so a flaky probe never blocks
// allocation. On platforms without a supported prober it is a no-op.
package netroute
