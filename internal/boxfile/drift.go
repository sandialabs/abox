package boxfile

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/sandialabs/abox/internal/config"
)

// FieldDiff describes one abox.yaml field whose declared value differs from the
// value persisted in an existing instance's config.yaml.
type FieldDiff struct {
	Field      string // dotted field name, e.g. "http.allow_private_targets"
	Declared   string // value declared in abox.yaml (human-readable)
	Current    string // value currently persisted for the instance
	HowToApply string // how the operator can make the declared value take effect
}

// String renders a single drift line for user-facing warnings.
func (d FieldDiff) String() string {
	return fmt.Sprintf("%s: abox.yaml=%s, instance=%s (%s)", d.Field, d.Declared, d.Current, d.HowToApply)
}

const (
	applyViaConfigEdit = "apply with `abox config edit` + `abox restart`"
	applyViaRecreate   = "apply by recreating the instance (`abox down --remove` then `abox up`)"
)

// Drift reports the abox.yaml-sourced fields that differ from an existing
// instance's persisted config. It is used by `abox up` to WARN that a re-run
// does not re-apply these fields to an existing instance (only the allowlist is
// reconciled), surfacing what would otherwise be a silent no-op.
//
// The allowlist is intentionally excluded (it is handled by the reconcile path).
// The SSH user is excluded because abox.yaml's default ("ubuntu") is
// indistinguishable from an unset value yet can legitimately differ from a
// base-image-derived user, which would produce false positives. Fields whose
// boxfile value is empty/unset (e.g. an omitted subnet that is auto-allocated)
// are not reported.
func Drift(box *Boxfile, inst *config.Instance) []FieldDiff {
	var diffs []FieldDiff
	diffs = append(diffs, resourceDrift(box, inst)...)
	diffs = append(diffs, httpDrift(box, inst)...)
	diffs = append(diffs, monitorDrift(box, inst)...)
	return diffs
}

// resourceDrift reports drift in resource and identity/network fields.
func resourceDrift(box *Boxfile, inst *config.Instance) []FieldDiff {
	var d []FieldDiff
	// Resources (mutable via `abox config edit` + restart / redefine).
	if box.CPUs != 0 && box.CPUs != inst.CPUs {
		d = append(d, mkDiff("cpus", strconv.Itoa(box.CPUs), strconv.Itoa(inst.CPUs), applyViaConfigEdit))
	}
	if box.Memory != 0 && box.Memory != inst.Memory {
		d = append(d, mkDiff("memory", strconv.Itoa(box.Memory), strconv.Itoa(inst.Memory), applyViaConfigEdit))
	}
	if box.Disk != "" && box.Disk != inst.Disk {
		d = append(d, mkDiff("disk", box.Disk, inst.Disk, applyViaConfigEdit))
	}
	if box.DNS.Upstream != "" && box.DNS.Upstream != inst.DNS.Upstream {
		d = append(d, mkDiff("dns.upstream", box.DNS.Upstream, inst.DNS.Upstream, applyViaConfigEdit))
	}
	// Identity / network (recreate-only).
	if box.Base != "" && box.Base != inst.Base {
		d = append(d, mkDiff("base", box.Base, inst.Base, applyViaRecreate))
	}
	if box.Subnet != "" && box.Subnet != inst.Subnet {
		d = append(d, mkDiff("subnet", box.Subnet, inst.Subnet, applyViaRecreate))
	}
	return d
}

// httpDrift reports drift in HTTP filter settings (applied at daemon startup;
// recreate/restart to apply).
func httpDrift(box *Boxfile, inst *config.Instance) []FieldDiff {
	var d []FieldDiff
	if box.GetMITM() != inst.HTTP.MITM {
		d = append(d, mkDiff("http.mitm", strconv.FormatBool(box.GetMITM()), strconv.FormatBool(inst.HTTP.MITM), applyViaRecreate))
	}
	if !slices.Equal(box.GetAllowPrivateTargets(), inst.HTTP.AllowPrivateTargets) {
		d = append(d, mkDiff("http.allow_private_targets", sliceStr(box.GetAllowPrivateTargets()), sliceStr(inst.HTTP.AllowPrivateTargets), applyViaRecreate))
	}
	if !slices.Equal(box.GetAllowedPorts(), inst.HTTP.AllowedPorts) {
		d = append(d, mkDiff("http.allowed_ports", intSliceStr(box.GetAllowedPorts()), intSliceStr(inst.HTTP.AllowedPorts), applyViaRecreate))
	}
	// max_connections: a persisted 0 means "use the default", so compare against
	// the effective value on both sides to avoid false drift on older instances.
	if box.GetMaxConnections() != effectiveMaxConns(inst.HTTP.MaxConnections) {
		d = append(d, mkDiff("http.max_connections", strconv.Itoa(box.GetMaxConnections()), strconv.Itoa(effectiveMaxConns(inst.HTTP.MaxConnections)), applyViaRecreate))
	}
	if !slices.Equal(box.GetSecretInjections(), inst.HTTP.SecretInjections) {
		d = append(d, mkDiff("http.secret_injections", injectionsStr(box.GetSecretInjections()), injectionsStr(inst.HTTP.SecretInjections), applyViaRecreate))
	}
	if !slices.Equal(box.GetMITMExceptions(), inst.HTTP.MITMExceptions) {
		d = append(d, mkDiff("http.mitm_exceptions", sliceStr(box.GetMITMExceptions()), sliceStr(inst.HTTP.MITMExceptions), applyViaRecreate))
	}
	return d
}

// monitorDrift reports drift in monitor settings (recreate-only).
func monitorDrift(box *Boxfile, inst *config.Instance) []FieldDiff {
	var d []FieldDiff
	if box.Monitor.Enabled != inst.Monitor.Enabled {
		d = append(d, mkDiff("monitor.enabled", strconv.FormatBool(box.Monitor.Enabled), strconv.FormatBool(inst.Monitor.Enabled), applyViaRecreate))
	}
	if box.Monitor.Version != "" && box.Monitor.Version != inst.Monitor.Version {
		d = append(d, mkDiff("monitor.version", box.Monitor.Version, inst.Monitor.Version, applyViaRecreate))
	}
	if box.GetKprobeMulti() != inst.Monitor.KprobeMulti {
		d = append(d, mkDiff("monitor.kprobe_multi", strconv.FormatBool(box.GetKprobeMulti()), strconv.FormatBool(inst.Monitor.KprobeMulti), applyViaRecreate))
	}
	if !slices.Equal(box.Monitor.Kprobes, inst.Monitor.Kprobes) {
		d = append(d, mkDiff("monitor.kprobes", sliceStr(box.Monitor.Kprobes), sliceStr(inst.Monitor.Kprobes), applyViaRecreate))
	}
	// monitor.policies in abox.yaml are relative paths, in config.yaml they are
	// resolved absolute paths — comparing raw strings would always report drift,
	// so only report a count change (added/removed policies).
	if len(box.Monitor.Policies) != len(inst.Monitor.Policies) {
		d = append(d, mkDiff("monitor.policies", plural(len(box.Monitor.Policies)), plural(len(inst.Monitor.Policies)), applyViaRecreate))
	}
	return d
}

func mkDiff(field, declared, current, how string) FieldDiff {
	return FieldDiff{Field: field, Declared: declared, Current: current, HowToApply: how}
}

func effectiveMaxConns(v int) int {
	if v == 0 {
		return config.DefaultHTTPMaxConnections
	}
	return v
}

func plural(n int) string { return strconv.Itoa(n) + " file(s)" }

func sliceStr(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%v", s)
}

func intSliceStr(s []int) string {
	if len(s) == 0 {
		return "(default)"
	}
	return fmt.Sprintf("%v", s)
}

func injectionsStr(s []config.SecretInjection) string {
	return strconv.Itoa(len(s)) + " binding(s)"
}
