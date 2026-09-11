package vmrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/sandialabs/abox/internal/errhint"
	"github.com/sandialabs/abox/internal/logging"
)

// VNetConfigKey is the inst.BackendConfig key under which the allocated VMware
// host-only network (e.g. "vmnet2") is persisted. The .vmx generator reads it to
// emit ethernet0.vnet (see vnetForInstance).
const VNetConfigKey = "vnet"

// vmnet allocation pool bounds. VMware Workstation numbers virtual networks
// vmnet0..vmnet19. Three are reserved by VMware's own defaults and MUST NOT be
// repurposed by abox:
//
//   - vmnet0: bridged (uplink to the physical LAN) — the OPPOSITE of what abox's
//     isolation model wants.
//   - vmnet1: the default host-only network.
//   - vmnet8: the default NAT network (has an uplink) — again, not host-only.
//
// abox allocates one host-only vmnet per instance from [2..19] EXCLUDING 8, so
// each instance is laterally isolated on its own switch with no uplink and no
// NAT. That yields at most 17 concurrent abox networks (vmnet2..vmnet19,
// excluding vmnet8).
const (
	vmnetPoolLow  = 2
	vmnetPoolHigh = 19
	vmnetNATNum   = 8 // reserved NAT default; excluded from the pool
)

// ErrVMNetExhausted is returned (wrapped in an errhint) when every allocatable
// vmnet number is already assigned.
var ErrVMNetExhausted = errors.New("no free VMware host-only vmnet available")

// regMu serializes access to the on-disk allocation registry within a process.
// abox is a single-threaded CLI, but Create paths and tests may run concurrent
// Allocate calls; the mutex plus atomic temp+rename writes keep the registry
// consistent. (Cross-process safety relies on config.AcquireLock at the call
// sites, mirroring subnet/port allocation.)
var regMu sync.Mutex

// registry is the JSON document persisted at the registry path. It maps an
// instance name to its allocated vmnet name (e.g. "myvm" -> "vmnet2"). Keying by
// instance name (not bridge) makes allocation idempotent per instance and keeps
// the mapping stable across bridge-name derivation.
type registry struct {
	// VNets maps instance name -> "vmnetN".
	VNets map[string]string `json:"vnets"`
}

// loadRegistry reads the registry file. A missing file yields an empty registry
// (first allocation). Caller must hold regMu.
func loadRegistry(regPath string) (*registry, error) {
	data, err := os.ReadFile(regPath)
	if errors.Is(err, os.ErrNotExist) {
		return &registry{VNets: map[string]string{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read vmnet registry: %w", err)
	}
	var r registry
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse vmnet registry %s: %w", regPath, err)
	}
	if r.VNets == nil {
		r.VNets = map[string]string{}
	}
	return &r, nil
}

// saveRegistry writes the registry atomically (temp file in the same dir + fsync
// + rename) so a crash never leaves a half-written or truncated registry, and no
// stray temp file survives a successful write. Caller must hold regMu.
func saveRegistry(regPath string, r *registry) error {
	if err := os.MkdirAll(filepath.Dir(regPath), 0o700); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal vmnet registry: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(regPath), ".vmware-vnets-*.tmp")
	if err != nil {
		return fmt.Errorf("create registry temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename; after a successful
	// rename the temp no longer exists so Remove is a harmless no-op.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write registry temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync registry temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close registry temp: %w", err)
	}
	if err := os.Rename(tmpName, regPath); err != nil {
		return fmt.Errorf("rename registry temp: %w", err)
	}
	return nil
}

// vmnetName formats a pool number as a vmnet interface name.
func vmnetName(n int) string { return "vmnet" + strconv.Itoa(n) }

// Allocate returns the vmnet name assigned to instance, allocating the lowest
// free number in [vmnetPoolLow..vmnetPoolHigh] excluding the reserved NAT number
// if none is assigned yet. It is idempotent: an instance that already has an
// allocation gets the same name back without consuming another slot.
//
// When the pool is exhausted it returns an *errhint.ErrHint wrapping
// ErrVMNetExhausted, explaining the 17-slot host-only vmnet pool.
func Allocate(regPath, instance string) (string, error) {
	regMu.Lock()
	defer regMu.Unlock()

	r, err := loadRegistry(regPath)
	if err != nil {
		return "", err
	}
	if existing, ok := r.VNets[instance]; ok {
		return existing, nil
	}

	// Build the set of numbers already in use.
	used := make(map[int]bool, len(r.VNets))
	for _, v := range r.VNets {
		if n, ok := parseVMNet(v); ok {
			used[n] = true
		}
	}

	for n := vmnetPoolLow; n <= vmnetPoolHigh; n++ {
		if n == vmnetNATNum || used[n] {
			continue
		}
		name := vmnetName(n)
		r.VNets[instance] = name
		if err := saveRegistry(regPath, r); err != nil {
			return "", err
		}
		return name, nil
	}

	return "", &errhint.ErrHint{
		Err: fmt.Errorf("%w (pool vmnet%d..vmnet%d excluding vmnet%d)", ErrVMNetExhausted, vmnetPoolLow, vmnetPoolHigh, vmnetNATNum),
		Hint: "abox allocates from a pool of 17 host-only vmnet slots " +
			"(vmnet2-vmnet19, excluding vmnet8) and dedicates one per instance " +
			"for isolation. Remove an unused instance (abox remove <name>) to " +
			"free a vmnet, then try again.",
	}
}

// Release removes instance's vmnet assignment from the registry. It is
// idempotent: releasing an unknown instance is a no-op returning nil.
func Release(regPath, instance string) error {
	regMu.Lock()
	defer regMu.Unlock()

	r, err := loadRegistry(regPath)
	if err != nil {
		return err
	}
	if _, ok := r.VNets[instance]; !ok {
		return nil
	}
	delete(r.VNets, instance)
	return saveRegistry(regPath, r)
}

// Lookup returns the vmnet assigned to instance and whether one exists.
//
// A malformed/unreadable registry is logged (not silently swallowed): a corrupt
// registry that reads as empty would make Exists=false and drive a re-Create /
// double-allocation, so it must be diagnosable. Callers on the teardown path use
// LookupErr if they need to surface the failure instead of degrading.
func Lookup(regPath, instance string) (string, bool) {
	v, ok, err := LookupErr(regPath, instance)
	if err != nil {
		logging.Warn("vmware vmnet registry unreadable; treating as no allocation", "path", regPath, "error", err)
		return "", false
	}
	return v, ok
}

// LookupErr is Lookup that surfaces a registry read/parse error instead of
// degrading to (",false"). Teardown paths use it so a corrupt registry does not
// silently leak a vmnet.
func LookupErr(regPath, instance string) (string, bool, error) {
	regMu.Lock()
	defer regMu.Unlock()

	r, err := loadRegistry(regPath)
	if err != nil {
		return "", false, err
	}
	v, ok := r.VNets[instance]
	return v, ok, nil
}

// AllocatedInstances returns the instance names that currently hold an
// allocation, sorted for deterministic output. Used by tests and diagnostics.
func AllocatedInstances(regPath string) []string {
	names, err := AllocatedInstancesErr(regPath)
	if err != nil {
		logging.Warn("vmware vmnet registry unreadable; treating as empty", "path", regPath, "error", err)
		return nil
	}
	return names
}

// AllocatedInstancesErr is AllocatedInstances that surfaces a registry
// read/parse error instead of degrading to nil.
func AllocatedInstancesErr(regPath string) ([]string, error) {
	regMu.Lock()
	defer regMu.Unlock()

	r, err := loadRegistry(regPath)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(r.VNets))
	for k := range r.VNets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// parseVMNet extracts the numeric suffix of a "vmnetN" name.
func parseVMNet(name string) (int, bool) {
	const prefix = "vmnet"
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return 0, false
	}
	n, err := strconv.Atoi(name[len(prefix):])
	if err != nil {
		return 0, false
	}
	return n, true
}

// HostOnlyConfig describes the host-only network abox wants for a vmnet. It is
// deliberately minimal and host-only by construction: there is NO field for an
// uplink/NAT because abox never wants one.
type HostOnlyConfig struct {
	VNet    string // "vmnet2"
	Subnet  string // network address, e.g. "10.10.10.0"
	Gateway string // host-side adapter IP, e.g. "10.10.10.1"
	Netmask string // e.g. "255.255.255.0"
}

// ConfigureHostOnly configures vmnet as a host-only network (no uplink, no NAT,
// DHCP left disabled — the guest gets its address via cloud-init). The mechanism
// is platform-specific (Windows vnetlib CLI vs. Linux/Fusion answer-file); the
// per-platform provisioner is selected at COMPILE TIME by activeProvisioner (see
// netcfg.go and the build-tagged netcfg_{linux,darwin,windows,other}.go).
//
// Defense-in-depth: guest->internet isolation does not rest SOLELY on this
// host-only topology. The privileged enforcer additionally installs a host-side
// FORWARD default-deny for the vmnet interface (the forwardChain family in
// internal/privilege/egress_linux.go, driven by
// internal/backend/vmware/egress_default.go), so even a host with ip_forward=1
// and a broad MASQUERADE covering the vmnet subnet drops forwarded guest traffic.
// This host-only config is the primary control; the FORWARD deny is the
// belt-and-suspenders backstop.
func ConfigureHostOnly(ctx context.Context, cfg HostOnlyConfig) error {
	p, err := activeProvisioner()
	if err != nil {
		return err
	}
	return p.configure(ctx, cfg)
}

// UnconfigureHostOnly tears down the host-only vmnet. Idempotent at the abox
// level: an already-removed vmnet is not treated as an error.
func UnconfigureHostOnly(ctx context.Context, vnet string) error {
	p, err := activeProvisioner()
	if err != nil {
		return err
	}
	return p.unconfigure(ctx, vnet)
}

// vnetlib verb/object/key tokens, shared by the Windows host-only command builder
// (windowsHostOnlyCmds in netcfg.go), the Windows provisioner (netcfg_windows.go),
// and their tests so the repeated argument strings stay in one place. They live in
// this portable file because windowsHostOnlyCmds is portable (kept Linux-tested).
const (
	vnetlibVerbAdd    = "add"
	vnetlibVerbSet    = "set"
	vnetlibVerbUpdate = "update"
	vnetlibObjAdapter = "adapter"
	vnetlibKeyAddr    = "addr"
	vnetlibKeyMask    = "mask"
)

// errUplinkForbidden sentinels a guard rejection so callers (e.g. the
// best-effort UnconfigureHostOnly) can distinguish "refused a dangerous
// argument" from "the command ran and failed".
var errUplinkForbidden = errors.New("uplink directive forbidden")

// uplinkTokens are the forbidden substrings that would (or could) attach an
// uplink to a vmnet, defeating host-only isolation. Matched case-insensitively
// as SUBSTRINGS so "--nat", "nat=yes", and "connectionType=nat" are all caught,
// not just bare tokens. "uplink"/"connectiontype" are included because an uplink
// could be enabled by a verb that never literally contains "nat"/"bridge".
//
//nolint:goconst // a security denylist reads clearer as bare literals than named constants
var uplinkTokens = []string{"nat", "bridge", "bridged", "uplink", "connectiontype"}

// assertNoUplink is a defense-in-depth guard that FAILS CLOSED if any command
// abox is about to run could attach an uplink to the vmnet (NAT, bridged, or any
// connection-type change). abox's security model requires host-only isolation;
// combined with runNetCmd (and assertNoUplinkConfig on the file-writer path, see
// netcfg.go) this makes "never NAT/bridged" a hard invariant enforced at the seam,
// on top of the hardcoded .vmx connectionType=hostonly.
//
// Matching is conservative: each argument is lower-cased and split on '-' and '='
// (so flag/assignment forms like "--nat" and "nat=yes" decompose) and every
// resulting fragment is checked as a substring against uplinkTokens. Erring
// toward over-rejection is deliberate — a false positive fails a command loudly;
// a false negative could silently weaken isolation.
func assertNoUplink(args []string) error {
	for _, a := range args {
		lower := strings.ToLower(a)
		fragments := append([]string{lower}, strings.FieldsFunc(lower, func(r rune) bool {
			return r == '-' || r == '='
		})...)
		for _, frag := range fragments {
			for _, tok := range uplinkTokens {
				if strings.Contains(frag, tok) {
					return fmt.Errorf("%w: refusing argument %q (matched %q): abox networks are host-only (no NAT, no bridge, no uplink)", errUplinkForbidden, a, tok)
				}
			}
		}
	}
	return nil
}
