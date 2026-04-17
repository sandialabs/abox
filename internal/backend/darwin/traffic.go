//go:build darwin

package darwin

import (
	"context"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
)

// TrafficInterceptor implements backend.TrafficInterceptor on macOS.
//
// Unlike libvirt's nwfilter (define XML once, attach per-run), pfctl rules
// scope by source IP, so the full rule set is loaded in one shot by
// setupPostBootFirewall once the VM IP is known. The interceptor methods are
// intentionally thin: Define/Apply/Remove/Delete are no-ops because rule
// application and teardown already happen in the start/stop/remove flows via
// firewall.PfctlClient. FilterExists is real, reading a marker file written by
// PfctlClient.ApplyInstanceRules, so status and doctor commands report
// accurate state.
type TrafficInterceptor struct{}

func (*TrafficInterceptor) DefineFilter(_ context.Context, _ *config.Instance) error {
	return nil
}

func (*TrafficInterceptor) ApplyFilter(_ context.Context, _, _, _, _ string, _ int) error {
	return nil
}

func (*TrafficInterceptor) RemoveFilter(_ context.Context, _, _, _ string, _ int) error {
	return nil
}

func (*TrafficInterceptor) DeleteFilter(_ context.Context, _ string) error {
	return nil
}

func (*TrafficInterceptor) FilterExists(filter string) bool {
	return firewall.FilterMarkerExists(filter)
}

func (*TrafficInterceptor) GetFilterUUID(_ string) string {
	return ""
}

// Compile-time interface check.
var _ backend.TrafficInterceptor = (*TrafficInterceptor)(nil)
