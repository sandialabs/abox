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

	ti := be.TrafficInterceptor()
	if ti == nil {
		return fmt.Errorf("backend %q does not support traffic interception", be.Name())
	}

	names := be.ResourceNames(name)
	ctx := context.Background()

	fmt.Fprintln(w, "Applying network filter...")

	fmt.Fprintln(w, "  Defining network filter...")
	logging.Debug("defining nwfilter", "filter", names.Filter)
	if err := ti.DefineFilter(ctx, inst); err != nil {
		return fmt.Errorf("failed to define nwfilter: %w", err)
	}

	fmt.Fprintln(w, "  Applying network filter...")
	logging.Debug("applying nwfilter", "vm", names.VM, "filter", names.Filter)
	if err := ti.ApplyFilter(ctx, name, inst.Bridge, names.Filter, inst.MACAddress, inst.CPUs); err != nil {
		// Roll back: remove the filter definition we just created
		_ = ti.DeleteFilter(ctx, names.Filter)
		return fmt.Errorf("failed to apply filter: %w", err)
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
