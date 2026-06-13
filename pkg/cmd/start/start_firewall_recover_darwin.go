//go:build darwin

package start

import (
	"context"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// recoverFirewall re-applies the per-instance pf rules for an already-running
// VM when they are missing. On darwin every egress control lives in the pf
// anchor (the TrafficInterceptor is a no-op), and that anchor can be lost
// without the VM dying — a prior start that timed out waiting for the VM IP,
// or an external `pfctl -F`. The already-running start path only recovers
// daemons, so without this a plain `abox start` would leave the sandbox open.
//
// Detection is cheap: ApplyInstanceRules writes a filter marker file, so
// FilterMarkerExists tells us whether rules are loaded without touching the
// privilege helper. When the marker is present we do nothing. When it is
// missing we must obtain the VM IP and re-apply via the shared
// setupPostBootFirewall path; if the running VM has no determinable IP we fail
// closed rather than leave it unfiltered.
func recoverFirewall(_ context.Context, w io.Writer, f *factory.Factory, be backend.Backend, name string, inst *config.Instance) error {
	filter := be.ResourceNames(name).Filter
	if firewall.FilterMarkerExists(filter) {
		return nil
	}

	fmt.Fprintln(w, "Traffic filter not active; re-applying...")

	// The VM is already running, so its IP should be available immediately;
	// waitForIP still gives a short grace period in case vmnet's lease lookup
	// is briefly unavailable.
	ip := waitForIP(w, be, name)
	if ip == "" {
		return fmt.Errorf("instance %q is running without traffic filtering and its IP could not be determined; run `abox stop %s` then `abox start %s`", name, name, name)
	}

	return setupPostBootFirewall(w, f, inst, name, ip)
}
