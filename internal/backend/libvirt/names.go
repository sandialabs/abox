//go:build linux

package libvirt

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/virsh"
)

// domainName returns the libvirt domain name for an instance, resolving the
// naming scheme from the instance config (the recorded bridge decides whether
// the instance is on the per-user or the legacy scheme — see
// config.Instance.UsesCurrentNames). Loading here keeps the many VMManager
// methods that receive only a bare name (Start/Stop/State/...) working without
// threading the full instance through every call site; it matches the GetIP
// precedent, and the YAML read is noise next to the virsh subprocess every
// caller execs with the result.
//
// When the config cannot be loaded (half-created instance, transient read
// error), fall back to the per-user derivation — the scheme every new instance
// is created under — and log it. The fallback deliberately never targets the
// legacy name, which on a shared host may be another user's domain. The cost:
// for a legacy instance the fallback names a domain that does not exist, so
// imperative operations (Start/Stop/...) fail with "not found" rather than act
// on the wrong domain, while existence-style callers (Exists, used by remove's
// cleanup) see false and may skip teardown — the legacy domain then leaks until
// cleaned up manually, which the Warn below is the only trace of.
func domainName(instanceName string) string {
	inst, _, err := config.Load(instanceName)
	if err != nil {
		fallback := config.DomainNameFor(os.Getuid(), instanceName)
		logging.Warn("could not load instance config to resolve domain name; assuming per-user scheme",
			"instance", instanceName, "domain", fallback, "error", err)
		return fallback
	}
	return inst.ResolvedVMName()
}

// UpgradeResourceNames moves an instance created under the legacy shared naming
// scheme (domain abox-<name>, name-only bridge, nwfilter abox-<name>-traffic) to
// the per-user scheme, so two users' same-named instances stop colliding on the
// host-global libvirtd/interface/iptables namespaces. It tears down the old-named
// objects (undefining the domain WITHOUT touching its storage), then commits the
// new identity by recording the per-user bridge in config — the normal start path
// recreates every object under the new names. The caller must ensure the VM is
// stopped. Implements backend.ResourceNameUpgrader; a no-op (false, nil) when the
// instance is already on the per-user scheme.
//
// Two invariants protect the teardown half:
//
//   - Ownership: legacy names derive from the instance name alone, so on a shared
//     host a same-named object may be ANOTHER USER'S. A legacy domain is only
//     torn down when one of its disks is this instance's disk; a legacy network
//     only when it declares this instance's recorded subnet. Unowned objects are
//     skipped (nothing of ours lives under them) and the upgrade still commits.
//   - Atomicity: teardown of an OWNED domain/network must succeed before the new
//     identity is committed — committing over a failed teardown would leave a
//     same-disk domain defined under the old name, or a stale network claiming
//     the subnet, wedging every subsequent start. A failed upgrade changes
//     nothing and retries cleanly on the next start. Only the nwfilter/iptables
//     flush stays best-effort: its leftovers are inert and re-flushable.
func (b *Backend) UpgradeResourceNames(ctx context.Context, inst *config.Instance, paths *config.Paths) (bool, error) {
	if inst.UsesCurrentNames() {
		return false, nil
	}

	oldVM := inst.ResolvedVMName()
	oldBridge := inst.Bridge

	// Every probe below fails CLOSED (error-aware existence and inspection):
	// committing the per-user identity while an owned object might still be
	// defined under the old name would leave a same-disk domain or a
	// subnet-claiming network behind, so an unanswerable probe aborts the
	// upgrade (nothing changed; the next start retries).
	domainOwned := false
	domainExists, err := virsh.DomainDefined(oldVM)
	if err != nil {
		return false, fmt.Errorf("cannot verify legacy-named domain exists during name upgrade of %q: %w", inst.Name, err)
	}
	if domainExists {
		disks, err := virsh.DomainDiskPaths(oldVM)
		if err != nil {
			return false, fmt.Errorf("cannot verify ownership of legacy-named domain during name upgrade of %q: %w", inst.Name, err)
		}
		domainOwned = slices.Contains(disks, paths.Disk)
		if !domainOwned {
			logging.Warn("legacy-named domain does not use this instance's disk (likely another user's same-named instance); leaving it alone",
				"instance", inst.Name, "domain", oldVM, "disk", paths.Disk)
		}
	}

	if domainOwned {
		// Positively shut off, not merely "not running": a paused/pmsuspended
		// domain is an active qemu still holding the disk, and a transient
		// domstate error must not green-light the teardown either.
		if !virsh.DomainIsShutOff(oldVM) {
			return false, fmt.Errorf("cannot upgrade resource names of %q while its VM (%s) is not shut off (state: %s)",
				inst.Name, oldVM, virsh.DomainState(oldVM))
		}
		if virsh.DomainHasSnapshots(oldVM) {
			return false, fmt.Errorf("cannot upgrade resource names of %q: domain %s has snapshots, which do not survive the rename; "+
				"delete them first (`abox snapshot delete`) and start again", inst.Name, oldVM)
		}
	}

	// The network/rules teardown targets inst.Bridge directly, so first require
	// the recorded bridge to actually BE this instance's legacy derivation: a
	// bridge recorded under another uid (a copied instance dir — the other way
	// UsesCurrentNames can be false) names ANOTHER USER'S current per-user
	// network, which must not be touched. The domain teardown above is immune
	// (ResolvedVMName always yields the legacy name-only form here).
	bridgeIsLegacyName := oldBridge == config.LegacyBridgeName(inst.Name)
	if !bridgeIsLegacyName {
		logging.Warn("recorded bridge is not this instance's legacy derivation (likely a copied instance dir); leaving the network and its host rules alone",
			"instance", inst.Name, "bridge", oldBridge)
	}

	// Network ownership: a defined legacy network is ours only when it declares
	// this instance's recorded subnet. The same probe stands in for the host
	// egress rules and nwfilter (both keyed on the bridge/instance name, neither
	// carrying anything ownership-verifiable of its own): an existing network
	// that is NOT ours means the name currently belongs to another user, so
	// their rules must not be flushed either. An absent network leaves any
	// leftover rules attributable to this instance's own past runs.
	networkExists, networkOwned := false, false
	if bridgeIsLegacyName {
		networkExists, err = virsh.NetworkDefined(oldBridge)
		if err != nil {
			return false, fmt.Errorf("cannot verify legacy-named network exists during name upgrade of %q: %w", inst.Name, err)
		}
		if networkExists {
			networkOwned, err = networkDeclaresSubnet(oldBridge, inst.Subnet)
			if err != nil {
				return false, fmt.Errorf("cannot verify ownership of legacy-named network during name upgrade of %q: %w", inst.Name, err)
			}
		}
	}

	// Flush the host egress rules keyed on the old bridge and delete the old
	// nwfilter. Remove resolves the legacy names itself (inst still records the
	// old bridge) and already logs failures with manual-cleanup guidance.
	// Best-effort: leftovers are inert and re-flushed on a later attempt.
	if bridgeIsLegacyName && (!networkExists || networkOwned) {
		if err := b.egress.Remove(ctx, inst); err != nil {
			logging.Warn("failed to remove legacy-named nwfilter during name upgrade; remove it manually with `virsh nwfilter-undefine`",
				"instance", inst.Name, "nwfilter", inst.ResolvedFilterName(), "error", err)
		}
	}

	// Undefine the old-named domain, keeping its disk: the next start redefines
	// the SAME storage under the new name.
	if domainOwned {
		if err := virsh.UndefineDomain(oldVM); err != nil {
			return false, fmt.Errorf("failed to undefine legacy-named domain %s during name upgrade of %q: %w", oldVM, inst.Name, err)
		}
	}

	// Delete the old-named network (ownership-gated, see above).
	if networkOwned {
		if err := virsh.DeleteNetwork(oldBridge); err != nil {
			return false, fmt.Errorf("failed to delete legacy-named network %s during name upgrade of %q: %w", oldBridge, inst.Name, err)
		}
	} else if networkExists {
		logging.Warn("legacy-named network does not declare this instance's subnet (likely another user's same-named instance); leaving it alone",
			"instance", inst.Name, "network", oldBridge, "subnet", inst.Subnet)
	}

	// Commit: from here every lookup resolves the per-user names.
	inst.Bridge = config.GenerateBridgeName(os.Getuid(), inst.Name)
	if err := config.Save(inst, paths); err != nil {
		return false, fmt.Errorf("failed to record per-user resource names for %q: %w", inst.Name, err)
	}

	logging.AuditInstance(inst.Name, "resource-names-upgrade",
		"old_domain", oldVM, "new_domain", inst.ResolvedVMName(),
		"old_bridge", oldBridge, "new_bridge", inst.Bridge)
	return true, nil
}

// networkDeclaresSubnet reports whether the named libvirt network declares the
// given IPv4 CIDR. Both sides are canonicalized through net.ParseCIDR so
// formatting differences don't defeat the match. The inspection error is
// propagated so ownership-gated teardown can fail closed on a transient probe
// failure (an unparseable recorded subnet reads as "not ours", which skips —
// safe in both directions).
func networkDeclaresSubnet(network, subnet string) (bool, error) {
	_, want, err := net.ParseCIDR(subnet)
	if err != nil {
		return false, nil
	}
	subnets, err := virsh.NetworkSubnets(network)
	if err != nil {
		return false, err
	}
	for _, n := range subnets {
		if n.String() == want.String() {
			return true, nil
		}
	}
	return false, nil
}
