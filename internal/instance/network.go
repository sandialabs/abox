package instance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

// CreateNetworkWithRetry creates the instance network, re-allocating the subnet
// and retrying (bounded) when the backend's post-define probe reports another
// defined network claimed the subnet concurrently (backend.ErrSubnetConflict —
// the cross-user allocate/define race, which no per-user lock can serialize;
// start can also hit it when another user's network claimed the recorded subnet
// while this instance's network was undefined, e.g. across the resource-name
// upgrade). The jittered pause breaks the lockstep where two racing creates
// both back out and both re-pick the same next /24: the slower one's
// re-allocation then sees the faster one's network as defined and skips past
// it. A user-chosen subnet (inst.SubnetPinned, recorded at create for
// --subnet/abox.yaml) is never re-allocated — external firewall rules or docs
// may be keyed on it — so the conflict surfaces as an error with guidance.
// Shared by create, start, and import; the caller must hold config.AcquireLock
// (Network().Create's documented contract).
func CreateNetworkWithRetry(ctx context.Context, w io.Writer, be backend.Backend, inst *config.Instance, paths *config.Paths) error {
	const maxAttempts = 3
	for attempt := 1; ; attempt++ {
		err := be.Network().Create(ctx, inst)
		if err == nil {
			return nil
		}
		if errors.Is(err, backend.ErrSubnetConflict) && inst.SubnetPinned {
			return fmt.Errorf("failed to create network: %w (the subnet was chosen explicitly at create; "+
				"free it on the host or recreate the instance with a different --subnet)", err)
		}
		if !errors.Is(err, backend.ErrSubnetConflict) || attempt == maxAttempts {
			return fmt.Errorf("failed to create network: %w", err)
		}
		fmt.Fprintf(w, "  Subnet %s was claimed concurrently; re-allocating...\n", inst.Subnet)
		time.Sleep(time.Duration(50+rand.IntN(200)) * time.Millisecond)

		subnet, gateway, _, aerr := backend.ResolveNetwork(be, "")
		if aerr != nil {
			return fmt.Errorf("failed to re-allocate subnet: %w", aerr)
		}
		inst.Subnet, inst.Gateway = subnet, gateway
		inst.IPAddress = config.DeriveHostIP(gateway)
		if serr := config.Save(inst, paths); serr != nil {
			return fmt.Errorf("failed to record re-allocated subnet: %w", serr)
		}
	}
}
