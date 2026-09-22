package instance

import (
	"context"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/logging"
)

// ApplyFiltered applies the network filter to a running instance,
// writing progress to w. This restricts the VM to only DNS and HTTP
// proxy traffic. When brief is true, the final summary is suppressed.
func ApplyFiltered(w io.Writer, name string, be backend.Backend, brief bool) error {
	logging.Debug("applying network filter", "instance", name)

	inst, _, err := LoadRunning(name, be.VM())
	if err != nil {
		return err
	}

	ec := be.EgressController()
	if ec == nil {
		return fmt.Errorf("backend %q does not support egress control", be.Name())
	}

	ctx := context.Background()

	fmt.Fprintln(w, "Applying network filter...")

	// Always (re)assert both halves of enforcement. Define installs the nwfilter
	// AND the privileged host iptables rules (DNS REDIRECT + accepts); Apply binds
	// the nwfilter to the live interface. Both are idempotent (the helper no-ops
	// when the rule set is already in force, so a running guest's REDIRECT is not
	// momentarily dropped). We must NOT gate this on the nwfilter-only Verify: the
	// nwfilter can be present while the host iptables rules were flushed (host
	// firewall reload, reboot, an older start flow), and skipping would leave the
	// guest's DNS un-redirected while reporting success.
	fmt.Fprintln(w, "  Defining network filter...")
	logging.Debug("defining egress policy", "instance", name)
	if err := ec.Define(ctx, inst, backend.BuildEgressPolicy(inst)); err != nil {
		return fmt.Errorf("failed to define egress policy: %w", err)
	}

	fmt.Fprintln(w, "  Applying network filter...")
	logging.Debug("applying egress policy", "instance", name)
	if err := ec.Apply(ctx, inst); err != nil {
		// Roll back: remove the policy we just defined
		_ = ec.Remove(ctx, inst)
		return fmt.Errorf("failed to apply egress policy: %w", err)
	}

	if !brief {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Instance %q network filter applied.\n", name)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Security restrictions are active:")
		fmt.Fprintln(w, "  - DNS allowlist enforced")
		fmt.Fprintln(w, "  - HTTP/HTTPS via proxy only (no direct connections)")
		fmt.Fprintln(w, "  - All other outbound traffic blocked")
	}

	logging.Audit("network filter applied",
		"action", logging.ActionSecurityFiltered,
		"instance", name,
	)

	return nil
}
