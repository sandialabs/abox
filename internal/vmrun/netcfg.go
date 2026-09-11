package vmrun

// Per-platform host-only network provisioning.
//
// VMware exposes no single cross-platform CLI for creating a host-only vmnet; the
// mechanism differs per platform:
//
//   - Windows: the `vnetlib.exe` CLI — `-- add adapter vmnetN`, `-- set adapter
//     vmnetN addr <gw>`, `-- set adapter vmnetN mask <mask>`, `-- update adapter
//     vmnetN`; removal `-- remove adapter vmnetN`. The leading `--` is mandatory.
//     See netcfg_windows.go.
//   - Linux: there is NO vnetlib CLI. Networking is file-based: edit
//     /etc/vmware/networking with `answer VNET_N_*` directives, then apply with
//     `vmware-networks --stop` / `--start`. See netcfg_linux.go.
//   - macOS (Fusion): there is NO vnetlib. The same `answer VNET_N_*` file lives at
//     "/Library/Preferences/VMware Fusion/networking"; apply with the Fusion.app
//     `vmnet-cli --configure` / `--stop` / `--start`. See netcfg_darwin.go.
//
// The active provisioner is chosen at COMPILE TIME via build tags: each platform
// file supplies activeProvisioner() and hostOnlyToolCandidates() (mirroring the
// egress controller's egress_darwin.go / egress_default.go split). The shared,
// GOOS-neutral pieces — the provisioner interface, the uplink guard, tool
// resolution, and the pure Windows command builder — live here so they stay
// unit-tested on the Linux CI host regardless of which handler is compiled.
//
// The Linux/Fusion answer-file engine and its pure transforms live in
// netcfg_answerfile.go (build: linux || darwin).
//
// EXPERIMENTAL: the Linux/Fusion file mechanism has not been validated on a real
// host. The command/directive builders are pure and unit-tested; the exact vendor
// verbs/paths need a live host to confirm (see TODO(real-host) notes).
//
// Every external command still funnels through runNetCmd -> assertNoUplink ->
// runCommand, and the file path enforces host-only *positively* (writes
// VIRTUAL_ADAPTER=yes + DHCP=no, writes no NAT/bridge stanza, and leaves every
// other VNET's lines untouched), so "never NAT/bridged" holds on both mechanisms.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// lookPath is the PATH-resolution seam (overridable in tests) so tool resolution
// can be exercised without VMware installed.
var lookPath = exec.LookPath

// networkingPathOverride, when non-empty, replaces the platform answer-file path.
// Test seam (SetNetworkingPathForTest) so cross-package tests can redirect the
// otherwise root-owned file to a temp location. It is consumed only by the
// answer-file provisioners (netcfg_answerfile.go), but the seam itself stays
// portable because SetNetworkingPathForTest has cross-package test callers
// (internal/backend/vmware) that must compile on every OS.
var networkingPathOverride string

// SetNetworkingPathForTest overrides the answer-file path used by the Linux/Fusion
// provisioners and returns a restore func. Test-only.
func SetNetworkingPathForTest(path string) func() {
	prev := networkingPathOverride
	networkingPathOverride = path
	return func() { networkingPathOverride = prev }
}

// SetLookPathForTest overrides tool resolution and returns a restore func so
// cross-package tests can fake a VMware install. Test-only.
func SetLookPathForTest(fn func(string) (string, error)) func() {
	prev := lookPath
	lookPath = fn
	return func() { lookPath = prev }
}

// hostOnlyProvisioner configures and tears down a single host-only vmnet on the
// current host. The concrete implementation is selected at compile time by
// activeProvisioner(), defined per platform in netcfg_{linux,darwin,windows,other}.go.
type hostOnlyProvisioner interface {
	configure(ctx context.Context, cfg HostOnlyConfig) error
	unconfigure(ctx context.Context, vnet string) error
}

// runNetCmd is the choke point for every networking-CLI invocation (vnetlib,
// vmware-networks, vmnet-cli). It runs assertNoUplink FIRST, so no path can attach
// an uplink, then dispatches through the shared runCommand seam.
func runNetCmd(ctx context.Context, bin string, args ...string) error {
	if err := assertNoUplink(args); err != nil {
		return err
	}
	_, err := runCommand(ctx, bin, args...)
	return err
}

// windowsHostOnlyCmds returns the vnetlib argument sequences to create a host-only
// vmnet (add adapter, set addr, set mask, update). It is a pure builder with no
// OS dependency, so it lives here (not in netcfg_windows.go) and stays unit-tested
// on the Linux CI host — the mask-bug regression guard (TestWindowsHostOnlyCmds)
// must keep running on the always-on Linux job.
//
// TODO(real-host): the object token for the addr/mask setters needs confirmation
// on a live Windows host. abox uses "adapter" for all four verbs
// (add/set-addr/set-mask/update); some docs use "vnet" for the setters
// (`set vnet NAME addr ADDRESS`). The Windows leg is not usable end-to-end anyway
// (no WFP egress enforcer — see docs/vmware.md §Platform support). Resolve by
// running `vnetlib -- set adapter ...` vs `set vnet ...` on a real host.
func windowsHostOnlyCmds(cfg HostOnlyConfig) [][]string {
	return [][]string{
		{"--", vnetlibVerbAdd, vnetlibObjAdapter, cfg.VNet},
		{"--", vnetlibVerbSet, vnetlibObjAdapter, cfg.VNet, vnetlibKeyAddr, cfg.Gateway},
		{"--", vnetlibVerbSet, vnetlibObjAdapter, cfg.VNet, vnetlibKeyMask, cfg.Netmask},
		{"--", vnetlibVerbUpdate, vnetlibObjAdapter, cfg.VNet},
	}
}

// ResolveHostOnlyTool resolves the host-only network tool for the current OS,
// returning its path or an error naming every candidate tried. Used by the
// checkdeps VMware preflight so a missing network CLI is surfaced before create.
// The candidate set is platform-specific (hostOnlyToolCandidates, build-tagged).
func ResolveHostOnlyTool() (string, error) {
	return resolveNetTool(hostOnlyToolCandidates()...)
}

// CheckVMRun runs `vmrun list` as an unprivileged functional probe: it confirms
// vmrun is not merely present but actually works (correct host type, licensed,
// hostd reachable). Returns vmrun's wrapped diagnostic on failure.
func CheckVMRun(ctx context.Context) error {
	_, err := vmrun(ctx, "list")
	return err
}

// assertNoUplinkConfig runs the uplink guard over the host-only config's own
// fields (defense-in-depth: a hostile VNet/subnet value carrying an uplink token
// is refused before it reaches the answer file or a vnetlib command).
//
// Stays portable: it is called by BOTH the Windows provisioner
// (netcfg_windows.go) and the answer-file provisioner (netcfg_answerfile.go), so
// it must not be relocated into either build-tagged file.
func assertNoUplinkConfig(cfg HostOnlyConfig) error {
	return assertNoUplink([]string{cfg.VNet, cfg.Subnet, cfg.Gateway, cfg.Netmask})
}

// resolveNetTool returns the first candidate that exists — an absolute path that
// stats, or a bare name found on PATH. On failure it names every candidate tried
// so a missing VMware install is diagnosable in one shot rather than surfacing as
// an opaque exec error mid-create.
func resolveNetTool(candidates ...string) (string, error) {
	for _, c := range candidates {
		if filepath.IsAbs(c) {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
			continue
		}
		if p, err := lookPath(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no VMware network tool found (tried %s); install VMware Workstation/Fusion",
		strings.Join(candidates, ", "))
}
