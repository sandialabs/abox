// Package firewall adapts the privileged egress helper client to the
// transport-neutral backend.EgressEnforcer interface used by backends to
// install host-side egress enforcement (iptables DNS REDIRECT + INPUT accepts).
package firewall

import (
	"context"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// egressEnforcer adapts an rpc.EgressClient to backend.EgressEnforcer.
type egressEnforcer struct {
	priv rpc.EgressClient
}

// NewEgressEnforcer wraps a privileged egress client as a backend.EgressEnforcer.
func NewEgressEnforcer(priv rpc.EgressClient) backend.EgressEnforcer {
	return &egressEnforcer{priv: priv}
}

// egressReq builds the rpc request describing the policy for a bridge. It is the
// single mapping from backend.EgressPolicy to the wire format the helper enforces.
func egressReq(bridge string, p backend.EgressPolicy) *rpc.EgressReq {
	return &rpc.EgressReq{
		Bridge:       bridge,
		DnsPort:      int32(p.DNSPort),      //nolint:gosec // port is 0-65535, fits int32
		HttpPort:     int32(p.HTTPPort),     //nolint:gosec // port is 0-65535, fits int32
		GuestDnsPort: int32(p.GuestDNSPort), //nolint:gosec // port is 0-65535, fits int32
		Gateway:      p.Gateway,
	}
}

// Apply installs the host-side egress rules for a bridge (idempotent).
func (e *egressEnforcer) Apply(ctx context.Context, bridge string, p backend.EgressPolicy) error {
	logging.Debug("applying egress rules", "bridge", bridge, "dns_port", p.DNSPort, "http_port", p.HTTPPort)

	cctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()

	if _, err := e.priv.Apply(cctx, egressReq(bridge, p)); err != nil {
		return err
	}

	logging.Audit("egress rules applied",
		"action", logging.ActionIptablesAddDNS,
		"bridge", bridge,
		"dns_port", p.DNSPort,
		"http_port", p.HTTPPort,
	)
	return nil
}

// Remove flushes the host-side egress rules for a bridge (idempotent). The
// policy's ports scope the flush to abox's own rules.
func (e *egressEnforcer) Remove(ctx context.Context, bridge string, p backend.EgressPolicy) error {
	logging.Debug("removing egress rules", "bridge", bridge)

	cctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()

	if _, err := e.priv.Remove(cctx, egressReq(bridge, p)); err != nil {
		return err
	}

	logging.Audit("egress rules flushed",
		"action", logging.ActionIptablesFlushDNS,
		"bridge", bridge,
	)
	return nil
}

// Verify reports whether the complete rule set described by the policy is in
// force on the bridge.
func (e *egressEnforcer) Verify(ctx context.Context, bridge string, p backend.EgressPolicy) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()

	resp, err := e.priv.Verify(cctx, egressReq(bridge, p))
	if err != nil {
		return false, err
	}
	return resp.GetOk(), nil
}
