package vmware

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/vmrun"
)

// NetworkManager implements backend.NetworkManager for VMware.
//
// Like libvirt, VMware uses a host-only (NO uplink, NO NAT) per-instance network
// for lateral isolation. The difference that matters for abox is how the network
// is named and created:
//
//  1. VMware host-only networks are identified by NUMBER (vmnetN), not by an
//     arbitrary name. So unlike libvirt's named abox-<name> network there is no
//     "define a network called abox-foo"; instead abox must ALLOCATE a free
//     vmnetN per instance and remember the mapping.
//  2. One vmnet per instance, host-only, so guest traffic has no route out.
//
// Because we cannot query VMware for free vmnets here (and to keep the mapping
// authoritative regardless of VMware's own state), abox maintains its OWN
// allocation registry (a JSON file under Paths.Base). See internal/vmrun for
// the registry and host-only configure/unconfigure helpers.
type NetworkManager struct{}

// registryPath returns the path to abox's vmnet allocation registry. It lives
// under Paths.Base (the user data dir), NOT under StorageDir: the mapping is
// abox metadata, one shared file across all instances, independent of where disk
// images live.
func registryPath(base string) string {
	return filepath.Join(base, "vmware-vnets.json")
}

// registryPathDefault resolves the registry path from the default user data dir.
// Used by the name-only lifecycle methods (Delete/Exists/IsActive) which don't
// carry an instance's StorageDir; the registry lives under Paths.Base regardless
// of StorageDir, so GetPaths("") — which returns the base without needing a real
// instance — is sufficient and correct.
func registryPathDefault() (string, error) {
	paths, err := config.GetPaths("")
	if err != nil {
		return "", err
	}
	return registryPath(paths.Base), nil
}

// hostOnlyConfigFor builds the host-only network parameters for an instance.
// Netmask is fixed /24 (abox subnets are always /24; see config.ValidateSubnet).
// subnetNetworkAddr derives the network address from inst.Subnet (which is CIDR
// "a.b.c.0/24").
func hostOnlyConfigFor(inst *config.Instance, vnet string) vmrun.HostOnlyConfig {
	return vmrun.HostOnlyConfig{
		VNet:    vnet,
		Subnet:  subnetNetworkAddr(inst.Subnet),
		Gateway: inst.Gateway,
		Netmask: "255.255.255.0",
	}
}

// subnetNetworkAddr strips the "/24" suffix from a CIDR subnet, returning the
// bare network address (e.g. "10.10.10.0/24" -> "10.10.10.0"). If there is no
// slash the input is returned unchanged.
func subnetNetworkAddr(cidr string) string {
	if addr, _, ok := strings.Cut(cidr, "/"); ok {
		return addr
	}
	return cidr
}

// Create allocates a host-only vmnet for the instance, persists the mapping, and
// configures the vmnet (subnet/gateway, host-only, no NAT). It is idempotent:
// re-running returns the same vmnet and re-asserts its configuration.
//
// Ordering assumption (documented for the wiring phase): the instance's
// config.yaml MUST already be saved to disk before Network().Create is called,
// because Create persists the allocated vnet back into config.yaml via
// config.Load/config.Save (so .vmx generation — which runs in VM().Create — sees
// BackendConfig["vnet"]). The instance lifecycle in internal/instance saves the
// config (subnet/gateway/bridge assigned) before materializing backend
// resources, and it materializes the network before the VM, so this holds. As a
// safety net, if config.Load fails (config not yet on disk), Create still sets
// inst.BackendConfig in memory so a caller that saves afterward and passes the
// same *inst into VM().Create still gets a correct .vmx.
func (m *NetworkManager) Create(ctx context.Context, inst *config.Instance) error {
	paths, err := config.GetPathsWithStorage(inst.Name, inst.StorageDir)
	if err != nil {
		return fmt.Errorf("resolve paths: %w", err)
	}
	reg := registryPath(paths.Base)

	// Was an allocation already present for this instance? Allocate is idempotent,
	// so on a retry it returns the existing vmnet. We must only release on failure
	// the allocation THIS call created — never one that predates us.
	_, existed, _ := vmrun.LookupErr(reg, inst.Name)

	vnet, err := vmrun.Allocate(reg, inst.Name)
	if err != nil {
		return err // already an errhint on exhaustion
	}

	// Self-clean on partial failure: if any step below fails, release the freshly
	// allocated vmnet back to the pool. Otherwise a privilege-denied answer-file
	// write or a config-save failure would permanently burn one of the ~16 pool
	// slots (Allocate persists the registry immediately), and a handful of failed
	// creates would exhaust the pool. Skipped when the allocation pre-existed.
	success := false
	defer func() {
		if success || existed {
			return
		}
		rollbackNetworkCreate(reg, inst, vnet)
	}()

	// Record the allocation in the in-memory instance so an immediate VM().Create
	// with this same *inst renders the right ethernet0.vnet even if the persist
	// below is a no-op path.
	if inst.BackendConfig == nil {
		inst.BackendConfig = map[string]any{}
	}
	inst.BackendConfig[vmrun.VNetConfigKey] = vnet

	// Persist the vnet into config.yaml so VM().Create/Redefine (which reloads the
	// instance) generates the .vmx against the allocated vmnet. Load honors the
	// instance's persisted StorageDir, mirroring the Phase-2 path fix.
	//
	// Persistence is LOAD-BEARING and its failure MUST surface: the in-memory set
	// above only covers the same-process create path. On a later `abox start`,
	// ensureNetwork skips Create (registry Exists is true) so the in-memory net
	// never runs, and VM().Redefine would render ethernet0.vnet from the fallback
	// inst.Bridge (e.g. "abox-dev") — pointing the NIC at a nonexistent network.
	// So if the config isn't loadable/savable here, fail loudly at create time
	// (with the ordering hint) rather than leaving a broken NIC to surface at
	// start. The documented ordering (config saved before Network().Create) makes
	// this the expected path; a Load failure means that ordering was violated.
	loaded, lpaths, lerr := config.Load(inst.Name)
	if lerr != nil {
		return fmt.Errorf("persist vnet allocation: cannot load instance config (it must be saved before network creation): %w", lerr)
	}
	if loaded.BackendConfig == nil {
		loaded.BackendConfig = map[string]any{}
	}
	loaded.BackendConfig[vmrun.VNetConfigKey] = vnet
	if err := config.Save(loaded, lpaths); err != nil {
		return fmt.Errorf("persist vnet allocation: %w", err)
	}

	// Configure the host-only vmnet (subnet/gateway, no NAT). Idempotent at the
	// abox level: re-adding an existing adapter is harmless. Persist happens first
	// (above) because ConfigureHostOnly mutates host-level state (/etc/vmware) and
	// needs root; on its failure the deferred rollback both releases the vmnet AND
	// clears the vnet we just persisted, so config.yaml never points at a released
	// allocation.
	if err := vmrun.ConfigureHostOnly(ctx, hostOnlyConfigFor(inst, vnet)); err != nil {
		return fmt.Errorf("configure host-only vmnet: %w", err)
	}
	success = true
	return nil
}

// rollbackNetworkCreate undoes a partial NetworkManager.Create: it releases the
// allocated vmnet back to the pool and clears the vnet that may have been
// persisted to config.yaml, so a failed create never leaves config.yaml pointing
// at a released allocation. Both steps are best-effort (failures are logged): a
// leaked pool slot or a stale pointer is recoverable, and the next create
// re-allocates and overwrites the pointer.
func rollbackNetworkCreate(reg string, inst *config.Instance, vnet string) {
	if rerr := vmrun.Release(reg, inst.Name); rerr != nil {
		logging.Warn("failed to release vmnet after partial network create; a pool slot may leak",
			"instance", inst.Name, "vnet", vnet, "error", rerr)
	}
	loaded, lpaths, lerr := config.Load(inst.Name)
	if lerr != nil || loaded.BackendConfig == nil {
		return
	}
	if _, ok := loaded.BackendConfig[vmrun.VNetConfigKey]; !ok {
		return
	}
	delete(loaded.BackendConfig, vmrun.VNetConfigKey)
	if serr := config.Save(loaded, lpaths); serr != nil {
		logging.Warn("failed to clear persisted vnet after partial network create",
			"instance", inst.Name, "error", serr)
	}
}

// Start is a no-op. A configured host-only vmnet is effectively always-on: the
// virtual switch and host adapter come up when ConfigureHostOnly's `update`
// applies and stay up until the adapter is removed. There is no per-boot
// "start network" step as libvirt has (virsh net-start). Documented as a no-op
// so the lifecycle's Network().Start call is a harmless success.
func (m *NetworkManager) Start(ctx context.Context, name string) error {
	return nil
}

// Stop is a no-op for the same reason as Start: abox does not tear the vmnet
// down on VM stop (other instances or a subsequent start reuse it); the vmnet is
// removed only at Delete. Stopping it here would disrupt a still-configured
// network unnecessarily.
func (m *NetworkManager) Stop(ctx context.Context, name string) error {
	return nil
}

// Delete unconfigures the instance's vmnet and releases it from the registry.
// It is idempotent: an instance with no allocation (already deleted) is a
// no-op success, and vnetlib "not found" on removal is ignored (see
// vmrun.UnconfigureHostOnly).
//
// name is the logical bridge name (inst.Bridge). It is mapped back to the
// instance name via the registry (see instanceForBridge).
func (m *NetworkManager) Delete(ctx context.Context, name string) error {
	reg, err := registryPathDefault()
	if err != nil {
		return fmt.Errorf("resolve registry path: %w", err)
	}

	// Surface registry-corruption on the teardown path: a malformed registry that
	// read as empty would make Delete a silent no-op and leak the vmnet, so we use
	// the error-returning variant here (unlike Exists, which is unprivileged/
	// read-only and degrades to false).
	instance, ok, err := instanceForBridgeErr(reg, name)
	if err != nil {
		return fmt.Errorf("read vmnet registry: %w", err)
	}
	if !ok {
		// No mapping: nothing allocated for this bridge; idempotent success.
		return nil
	}

	vnet, ok, err := vmrun.LookupErr(reg, instance)
	if err != nil {
		return fmt.Errorf("read vmnet registry: %w", err)
	}
	if ok {
		if err := vmrun.UnconfigureHostOnly(ctx, vnet); err != nil {
			return fmt.Errorf("unconfigure host-only vmnet: %w", err)
		}
	}
	return vmrun.Release(reg, instance)
}

// Exists reports whether the registry holds an allocation for the given bridge
// name. "Defined" for a VMware host-only network means abox has allocated a
// vmnet for it (there is no separate libvirt-style definition object).
func (m *NetworkManager) Exists(name string) bool {
	reg, err := registryPathDefault()
	if err != nil {
		return false
	}
	_, ok := instanceForBridge(reg, name)
	return ok
}

// IsActive mirrors Exists: a host-only vmnet is active whenever it is configured
// (there is no separate "started" state at the abox level; see Start). A real
// host could additionally probe `vnetlib -- status vmnetN`, but that requires
// the tools and is deferred.
//
// TODO(real-host): optionally verify the adapter is actually up via a status
// probe through the runCommand seam.
func (m *NetworkManager) IsActive(name string) bool {
	return m.Exists(name)
}

// instanceForBridge reverse-maps a bridge name (config.GenerateBridgeName output,
// "abox-<name>" or "ab-<hash>") to the instance name that owns it, by matching
// the bridge each registered instance would generate. This is the simplest
// correct approach given GenerateBridgeName hashes long names (so a bridge is not
// always literally reversible to a name): we recompute the bridge for each
// instance the registry knows about and compare.
func instanceForBridge(regPath, bridge string) (string, bool) {
	for _, instance := range vmrun.AllocatedInstances(regPath) {
		if config.GenerateBridgeName(instance) == bridge {
			return instance, true
		}
	}
	return "", false
}

// instanceForBridgeErr is instanceForBridge that surfaces a registry read/parse
// error, for the teardown path where a corrupt registry must not be swallowed.
func instanceForBridgeErr(regPath, bridge string) (string, bool, error) {
	instances, err := vmrun.AllocatedInstancesErr(regPath)
	if err != nil {
		return "", false, err
	}
	for _, instance := range instances {
		if config.GenerateBridgeName(instance) == bridge {
			return instance, true, nil
		}
	}
	return "", false, nil
}
