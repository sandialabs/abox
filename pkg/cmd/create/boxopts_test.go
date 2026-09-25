package create

import (
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/boxfile"
	"github.com/sandialabs/abox/internal/config"
)

// knownBoxfileKeys is every yaml key reachable in abox.yaml, and how it gets
// applied. Keys marked "not mapped" are deliberately not part of the
// Boxfile -> create.Options mapping; everything else must be assigned in
// applyBoxfile.
//
// This list exists because abox.yaml used to be mapped in two places that
// drifted apart, silently dropping http.secret_injections, http.mitm_exceptions,
// http.max_connections and monitor.kprobe_multi from `abox up` and allowlist
// from `abox create --from-file`. TestBoxfileKeysAreAccountedFor fails when a
// new key appears in neither this list nor the mapping.
var knownBoxfileKeys = map[string]string{
	"version":                    "not mapped: format metadata, consumed by the loader's version check",
	"name":                       "not mapped: passed to runCreate as the instance name argument",
	"provision":                  "not mapped: consumed by pkg/cmd/up via box.ResolveProvisionPaths",
	"overlay":                    "not mapped: consumed by pkg/cmd/up via box.ResolveOverlayPath",
	"overrides":                  "not mapped: backend-scoped, becomes TemplateContent in loadBackendOverrides",
	"backend":                    "Options.BackendName",
	"cpus":                       "Options.CPUs",
	"memory":                     "Options.Memory",
	"disk":                       "Options.Disk",
	"base":                       "Options.Base",
	"user":                       "Options.User",
	"subnet":                     "Options.Subnet",
	"allowlist":                  "Options.Allowlist",
	"dns.upstream":               "Options.Upstream",
	"http.mitm":                  "Options.MITM",
	"http.max_connections":       "Options.MaxConnections",
	"http.allow_private_targets": "Options.AllowPrivateTargets",
	"http.allowed_ports":         "Options.AllowedPorts",
	"http.secret_injections":     "Options.SecretInjections",
	"http.mitm_exceptions":       "Options.MITMExceptions",
	"monitor.enabled":            "Options.MonitorEnabled",
	"monitor.version":            "Options.MonitorVersion",
	"monitor.kprobe_multi":       "Options.MonitorKprobeMulti",
	"monitor.kprobes":            "Options.MonitorKprobes",
	"monitor.policies":           "Options.MonitorPolicies",
}

// TestBoxfileKeysAreAccountedFor walks the yaml tags of boxfile.Boxfile and
// fails when a key is neither mapped by applyBoxfile nor explicitly listed as
// unmapped. It is the guard against the abox.yaml -> create.Options mapping
// silently dropping a newly added key.
func TestBoxfileKeysAreAccountedFor(t *testing.T) {
	found := yamlLeafKeys(reflect.TypeFor[boxfile.Boxfile](), "")

	for _, key := range found {
		if _, ok := knownBoxfileKeys[key]; !ok {
			t.Errorf("unexpected abox.yaml key %q: map it in applyBoxfile and add it to "+
				"knownBoxfileKeys, or add it there with a \"not mapped: <reason>\" note", key)
		}
	}

	seen := make(map[string]bool, len(found))
	for _, key := range found {
		seen[key] = true
	}
	var stale []string
	for key := range knownBoxfileKeys {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("knownBoxfileKeys lists keys that no longer exist in boxfile.Boxfile: %v", stale)
	}
}

// mappedBoxfileKeys returns the abox.yaml keys knownBoxfileKeys claims are
// mapped, keyed to the create.Options field each one claims to feed.
func mappedBoxfileKeys(t *testing.T) map[string]string {
	t.Helper()
	mapped := make(map[string]string)
	for key, note := range knownBoxfileKeys {
		if strings.HasPrefix(note, "not mapped:") {
			continue
		}
		field, ok := strings.CutPrefix(note, "Options.")
		if !ok {
			t.Errorf("knownBoxfileKeys[%q] = %q, want %q or a %q note",
				key, note, "Options.<Field>", "not mapped: <reason>")
			continue
		}
		mapped[key] = field
	}
	return mapped
}

// TestKnownBoxfileKeys_NameRealOptionsFields stops the accounting list from
// being satisfied by a plausible-looking string. Without this, adding a key
// with a note like "Options.ThisDoesNotExist" and mapping it nowhere keeps the
// suite green — the guard would be enforcing human diligence, not the mapping.
func TestKnownBoxfileKeys_NameRealOptionsFields(t *testing.T) {
	optsType := reflect.TypeFor[Options]()
	for key, field := range mappedBoxfileKeys(t) {
		if _, ok := optsType.FieldByName(field); !ok {
			t.Errorf("knownBoxfileKeys[%q] names create.Options.%s, which does not exist", key, field)
		}
	}
}

// yamlLeafKeys returns the dotted yaml paths of every leaf field of t. Structs
// are recursed into; slices and maps are leaves (a []SecretInjection is one
// abox.yaml key, not four).
//
// It mirrors how yaml.v3 actually binds keys, not just how they are tagged: an
// untagged exported field is bound under its lowercased name, and a ",inline"
// field's keys appear at the parent level. Both are accepted by the strict
// loader, so both must be visible here — a walker that only saw explicit tags
// would let the two most natural ways of adding a field slip past the guard.
func yamlLeafKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for f := range t.Fields() {
		if f.PkgPath != "" { // unexported
			continue
		}
		tag, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == "-" {
			continue
		}

		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}

		// An inline struct contributes its own fields at this level.
		if tag == "" && slices.Contains(strings.Split(opts, ","), "inline") && ft.Kind() == reflect.Struct {
			keys = append(keys, yamlLeafKeys(ft, prefix)...)
			continue
		}
		if tag == "" {
			tag = strings.ToLower(f.Name)
		}

		path := tag
		if prefix != "" {
			path = prefix + "." + tag
		}
		if ft.Kind() == reflect.Struct {
			keys = append(keys, yamlLeafKeys(ft, path)...)
			continue
		}
		keys = append(keys, path)
	}
	return keys
}

// TestApplyBoxfile_MapsKnownFields pins the value each abox.yaml key lands on.
// TestBoxfileKeysAreAccountedFor proves nothing is forgotten; this proves each
// key reaches the right field.
func TestApplyBoxfile_MapsKnownFields(t *testing.T) {
	// boxDir must be a real directory: ResolvePolicyPaths rejects a relative
	// path against an empty base ("" cleans to ".", so the join escapes it).
	boxDir := t.TempDir()

	mitm := false
	maxConns := 1024
	kprobeMulti := true
	box := &boxfile.Boxfile{
		Version:   1,
		Name:      "mapped",
		Backend:   "libvirt",
		CPUs:      6,
		Memory:    9001,
		Disk:      "40G",
		Base:      "ubuntu-22.04",
		User:      "tester",
		Subnet:    "192.168.77.0/24",
		Allowlist: []string{"example.com"},
		DNS:       boxfile.BoxfileDNS{Upstream: "1.1.1.1:53"},
		HTTP: boxfile.BoxfileHTTP{
			MITM:                &mitm,
			MaxConnections:      &maxConns,
			AllowPrivateTargets: []string{"10.0.0.0/8"},
			AllowedPorts:        []int{8443},
			SecretInjections: []config.SecretInjection{
				{Key: "k", Host: "api.example.com", Header: "x-api-key"},
			},
			MITMExceptions: []string{"pinned.example.com"},
		},
		Monitor: boxfile.BoxfileMonitor{
			Enabled:     true,
			Version:     "v1.2.3",
			KprobeMulti: &kprobeMulti,
			Kprobes:     []string{"security_bprm_check"},
			Policies:    []string{"policy.yaml"},
		},
	}

	var opts Options
	if err := applyBoxfile(&opts, box, boxDir); err != nil {
		t.Fatalf("applyBoxfile() error = %v", err)
	}

	checks := []struct {
		key  string
		got  any
		want any
	}{
		{"backend", opts.BackendName, "libvirt"},
		{"cpus", opts.CPUs, 6},
		{"memory", opts.Memory, 9001},
		{"disk", opts.Disk, "40G"},
		{"base", opts.Base, "ubuntu-22.04"},
		{"user", opts.User, "tester"},
		{"subnet", opts.Subnet, "192.168.77.0/24"},
		{"allowlist", opts.Allowlist, []string{"example.com"}},
		{"dns.upstream", opts.Upstream, "1.1.1.1:53"},
		{"http.mitm", opts.MITM, false},
		{"http.max_connections", opts.MaxConnections, 1024},
		{"http.allow_private_targets", opts.AllowPrivateTargets, []string{"10.0.0.0/8"}},
		// A non-default port: a mapping that silently fell back to the built-in
		// 80/443 defaults would still be caught here.
		{"http.allowed_ports", opts.AllowedPorts, []int{8443}},
		{"http.secret_injections", opts.SecretInjections, box.HTTP.SecretInjections},
		{"http.mitm_exceptions", opts.MITMExceptions, []string{"pinned.example.com"}},
		{"monitor.enabled", opts.MonitorEnabled, true},
		{"monitor.version", opts.MonitorVersion, "v1.2.3"},
		{"monitor.kprobe_multi", opts.MonitorKprobeMulti, true},
		{"monitor.kprobes", opts.MonitorKprobes, []string{"security_bprm_check"}},
		{"monitor.policies", opts.MonitorPolicies, []string{boxDir + "/policy.yaml"}},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("applyBoxfile() %s = %v, want %v", c.key, c.got, c.want)
		}
	}

	// Every key knownBoxfileKeys claims is mapped must be asserted above.
	// Otherwise a key can be listed and mapped but never value-checked, and a
	// wrong mapping (memory into CPUs, say) goes unnoticed.
	asserted := make(map[string]bool, len(checks))
	for _, c := range checks {
		asserted[c.key] = true
	}
	for key := range mappedBoxfileKeys(t) {
		if !asserted[key] {
			t.Errorf("abox.yaml key %q is mapped by applyBoxfile but not asserted here; "+
				"add it to checks so a wrong mapping is caught", key)
		}
	}
}

// TestApplyBoxfile_AppliesDefaultsForUnsetPointers checks the three
// pointer-guarded keys fall back to their documented defaults rather than the
// Go zero value: MITM on, 512 connections, kprobe_multi off.
func TestApplyBoxfile_AppliesDefaultsForUnsetPointers(t *testing.T) {
	var opts Options
	if err := applyBoxfile(&opts, boxfile.DefaultBoxfile(), t.TempDir()); err != nil {
		t.Fatalf("applyBoxfile() error = %v", err)
	}

	if !opts.MITM {
		t.Error("applyBoxfile() MITM = false, want true (secure default)")
	}
	if opts.MaxConnections != config.DefaultHTTPMaxConnections {
		t.Errorf("applyBoxfile() MaxConnections = %d, want %d",
			opts.MaxConnections, config.DefaultHTTPMaxConnections)
	}
	if opts.MonitorKprobeMulti {
		t.Error("applyBoxfile() MonitorKprobeMulti = true, want false")
	}
}
