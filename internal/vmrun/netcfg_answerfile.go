//go:build linux || darwin

package vmrun

// Answer-file host-only mechanism, shared by Linux and macOS/Fusion. Both edit a
// VMware "networking" file (`answer VNET_N_*` directives) and apply the change
// with a vendor restart command; they differ only in the file PATH and the apply
// TOOL, which each platform file (netcfg_linux.go / netcfg_darwin.go) supplies via
// activeProvisioner(). The pure transforms below are unit-tested on the Linux CI
// host (this file builds under linux || darwin).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Shared vendor restart verbs for the answer-file apply step. Both Linux
// (vmware-networks) and Fusion (vmnet-cli) take --stop/--start; Fusion prefixes a
// --configure. Defined here (linux || darwin) so both activeProvisioner builders
// reference the same tokens.
const (
	applyStop  = "--stop"
	applyStart = "--start"
)

// networkingPathOr returns the test override when set, else def. Only the
// answer-file provisioners (linux/darwin) resolve a networking-file path, so it
// lives here rather than in the untagged netcfg.go (where it is unused on
// windows). networkingPathOverride itself stays in netcfg.go, visible to all.
func networkingPathOr(def string) string {
	if networkingPathOverride != "" {
		return networkingPathOverride
	}
	return def
}

// fileProvisioner edits a VMware "networking" answer-file and applies the change
// with a vendor restart command. Linux and Fusion share the file FORMAT
// (`answer VNET_N_*`) and differ only in the file path and the apply tool.
type fileProvisioner struct {
	// networkingPath is the answer-file to edit (overridable for tests).
	networkingPath string
	// toolCandidates are the apply-tool names/paths tried in order.
	toolCandidates []string
	// applyArgs are the restart invocations run after the file is written, in
	// order (e.g. [["--stop"],["--start"]] or [["--configure"],["--stop"],["--start"]]).
	applyArgs [][]string
}

// netFileMu serializes answer-file read-modify-write within the process. Cross-
// process safety relies on the caller holding config.AcquireLock around create/
// remove (mirroring the vmnet registry and subnet/port allocation) — we do NOT
// re-acquire it here, since it is a held global singleton.
var netFileMu sync.Mutex

func (p fileProvisioner) configure(ctx context.Context, cfg HostOnlyConfig) error {
	if err := assertNoUplinkConfig(cfg); err != nil {
		return err
	}
	netFileMu.Lock()
	defer netFileMu.Unlock()

	existing, err := readNetworkingFile(p.networkingPath)
	if err != nil {
		return err
	}
	updated, err := applyHostOnlyDirectives(existing, cfg)
	if err != nil {
		return err
	}
	if err := writeNetworkingFile(p.networkingPath, updated); err != nil {
		return err
	}
	return p.apply(ctx)
}

func (p fileProvisioner) unconfigure(ctx context.Context, vnet string) error {
	if err := assertNoUplink([]string{vnet}); err != nil {
		return err
	}
	netFileMu.Lock()
	defer netFileMu.Unlock()

	existing, err := readNetworkingFile(p.networkingPath)
	if err != nil {
		return err
	}
	updated, removed := removeHostOnlyDirectives(existing, vnet)
	if !removed {
		// Nothing for this vnet in the file: idempotent success, no restart needed.
		return nil
	}
	if err := writeNetworkingFile(p.networkingPath, updated); err != nil {
		return err
	}
	return p.apply(ctx)
}

// apply resolves the vendor tool and runs each restart invocation in order.
func (p fileProvisioner) apply(ctx context.Context) error {
	bin, err := resolveNetTool(p.toolCandidates...)
	if err != nil {
		return err
	}
	for _, args := range p.applyArgs {
		if err := runNetCmd(ctx, bin, args...); err != nil {
			return fmt.Errorf("%s %v failed: %w", filepath.Base(bin), args, err)
		}
	}
	return nil
}

// ---- answer-file transforms (pure; unit-tested) --------------------------

// hostOnlyDirectives are the per-VNET keys abox manages. VIRTUAL_ADAPTER=yes +
// DHCP=no assert host-only positively; an explicit NAT=no is the topological half
// of the isolation guarantee.
//
// The NAT key is written explicitly as "no" rather than omitted, to be robust
// across Workstation/Fusion versions. This "no" is safe by construction — it
// DISABLES NAT — and the assertNoUplink guard, which would reject a NAT-enabling
// directive, only screens the config fields and apply-command args, not these
// self-authored host-only lines.
func hostOnlyDirectives(cfg HostOnlyConfig) []string {
	n := vnetNum(cfg.VNet)
	return []string{
		fmt.Sprintf("answer VNET_%d_HOSTONLY_SUBNET %s", n, cfg.Subnet),
		fmt.Sprintf("answer VNET_%d_HOSTONLY_NETMASK %s", n, cfg.Netmask),
		fmt.Sprintf("answer VNET_%d_VIRTUAL_ADAPTER yes", n),
		fmt.Sprintf("answer VNET_%d_NAT no", n),
		fmt.Sprintf("answer VNET_%d_DHCP no", n),
	}
}

// networkingVersionHeader is the first line VMware writes in the networking
// answer-file. abox seeds it when creating the file on a host that has none yet,
// and preserves it verbatim otherwise.
const networkingVersionHeader = "VERSION=1,0"

// applyHostOnlyDirectives returns existing with this VNET's answer lines replaced
// by the host-only set. Every line belonging to a DIFFERENT VNET (or none) is
// preserved verbatim, so an existing VNET_8_NAT yes is never disturbed.
func applyHostOnlyDirectives(existing string, cfg HostOnlyConfig) (string, error) {
	n := vnetNum(cfg.VNet)
	if n < 0 {
		return "", fmt.Errorf("invalid vmnet name %q", cfg.VNet)
	}
	kept := dropVNetLines(existing, n)
	kept = ensureVersionHeader(kept)
	kept = append(kept, hostOnlyDirectives(cfg)...)
	return joinNetworkingLines(kept), nil
}

// ensureVersionHeader prepends the VMware "VERSION=1,0" header when lines has no
// VERSION= line yet (a networking file abox is creating from empty). If a version
// header already exists it is left in place, wherever it sits.
func ensureVersionHeader(lines []string) []string {
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "VERSION=") {
			return lines
		}
	}
	return append([]string{networkingVersionHeader}, lines...)
}

// removeHostOnlyDirectives returns existing without any of this VNET's answer
// lines, and whether anything was removed.
func removeHostOnlyDirectives(existing, vnet string) (string, bool) {
	n := vnetNum(vnet)
	if n < 0 {
		return existing, false
	}
	kept := dropVNetLines(existing, n)
	before := len(splitNetworkingLines(existing))
	if len(kept) == before {
		return existing, false
	}
	return joinNetworkingLines(kept), true
}

// dropVNetLines returns the lines of content with every `answer VNET_<n>_...`
// line for exactly n removed (VNET_1 is not confused with VNET_10).
func dropVNetLines(content string, n int) []string {
	prefix := fmt.Sprintf("answer VNET_%d_", n)
	var kept []string
	for _, line := range splitNetworkingLines(content) {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			continue
		}
		kept = append(kept, line)
	}
	return kept
}

// splitNetworkingLines splits into lines, dropping a single trailing empty line
// from the final newline so round-trips do not accumulate blank lines.
func splitNetworkingLines(content string) []string {
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// joinNetworkingLines re-joins lines with a single trailing newline.
func joinNetworkingLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// vnetNum returns the numeric suffix of a "vmnetN" name, or -1 if malformed.
func vnetNum(vnet string) int {
	if n, ok := parseVMNet(vnet); ok {
		return n
	}
	return -1
}

// ---- file IO -------------------------------------------------------------

// readNetworkingFile reads the answer-file; a missing file is an empty document
// (first VNET on a host whose networking file has not been created yet).
func readNetworkingFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read VMware networking file %s: %w", path, err)
	}
	return string(data), nil
}

// writeNetworkingFile writes content atomically (temp in the same dir + rename).
//
// TODO(real-host): the networking file is root-owned; this write (and the vendor
// restart) require privilege. For now abox must be invoked with sufficient
// privilege for VMware network create. Routing these through the privilege helper
// is a separate, sized workstream (new RPC + a trust-boundary validator), NOT done
// here — see the plan.
func writeNetworkingFile(path, content string) error {
	dir := filepath.Dir(path)
	// 0755, not 0750: the VMware networking dir (e.g. /etc/vmware) must stay
	// world-traversable so non-root VMware helpers can reach the networking file;
	// this matches the vendor default and only applies when abox creates the dir.
	//nolint:gosec // G301: 0755 is deliberate for VMware helper traversal (see above)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create networking dir %s (VMware network config needs root): %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".networking-*.tmp")
	if err != nil {
		return fmt.Errorf("create networking temp in %s (VMware network config needs root): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	// Preserve the existing file's mode so abox's edit does not silently tighten
	// the vendor file (CreateTemp makes 0600; the vendor networking file is
	// typically 0644 and other VMware helpers may need to read it). Default to
	// 0644 when the file does not exist yet.
	mode := os.FileMode(0o644)
	if fi, statErr := os.Stat(path); statErr == nil {
		mode = fi.Mode().Perm()
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod networking temp: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write networking temp: %w", err)
	}
	// fsync before rename so a crash can't leave a zero-length/partial file in
	// place (matches saveRegistry's durability for the atomic-rename to mean it).
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync networking temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close networking temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install networking file %s (VMware network config needs root): %w", path, err)
	}
	return nil
}
