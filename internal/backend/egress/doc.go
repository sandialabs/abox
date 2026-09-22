// Package egress holds the shared, embeddable egress-controller machinery for the
// VM backends. Each host enforcement mechanism contributes one build-tagged base:
//
//   - PfBase (darwin, pf_darwin.go) — the pf (pfctl) machinery used by every macOS
//     backend (vfkit and vmware/Fusion), which confine a guest with a per-instance
//     pf anchor (abox/<instance>) keyed on the instance's deterministic /24 subnet.
//   - IptablesBase (!darwin, iptables.go) — the iptables machinery shared by the
//     libvirt and vmware backends on Linux/Windows.
//
// The parts that are IDENTICAL across backends of a mechanism live here as an
// embeddable base; the parts that legitimately DIFFER — Define/Apply, i.e. WHEN
// the per-instance rules are loaded, plus each backend's own Verify/Remove where
// they diverge — stay in each backend. For pf specifically: vfkit learns its bridge
// (bridge100) only after the VM starts, so it loads the anchor in Apply; vmware
// records its vmnet interface pre-boot, so it loads in Define and no-ops Apply.
//
// A mechanism base is compiled only on the platforms that use it (pf is darwin-only;
// iptables is !darwin), so the two type names never collide. This package mirrors
// firewall (rule building) and privilege (the privileged enforcer surfaces), while
// living under internal/backend/ next to the controllers it serves.
package egress
