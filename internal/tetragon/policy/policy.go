// Package policy provides Tetragon tracing policy generation from a curated kprobe registry.
package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// TracingPolicy represents a Tetragon TracingPolicy CRD.
type TracingPolicy struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   TracingPolicyMeta `yaml:"metadata"`
	Spec       TracingPolicySpec `yaml:"spec"`
}

// TracingPolicyMeta holds metadata for the tracing policy.
type TracingPolicyMeta struct {
	Name string `yaml:"name"`
}

// TracingPolicySpec holds the spec for the tracing policy.
type TracingPolicySpec struct {
	Kprobes []KprobeSpec `yaml:"kprobes"`
}

// KprobeSpec defines a single kprobe in a tracing policy.
type KprobeSpec struct {
	Call string `yaml:"call"`
	// Emit syscall: false explicitly — Tetragon v1.6+ defaults to syscall
	// resolution when the field is absent, prepending __x64_ to all function
	// names (even non-syscalls like security_file_open), which causes probe
	// attachment to silently fail.
	Syscall   bool           `yaml:"syscall"`
	Return    bool           `yaml:"return,omitempty"`
	Ignore    *KprobeIgnore  `yaml:"ignore,omitempty"`
	Args      []KprobeArg    `yaml:"args"`
	ReturnArg *KprobeArg     `yaml:"returnArg,omitempty"`
	Selectors []SelectorSpec `yaml:"selectors"`
}

// KprobeIgnore configures how Tetragon handles kprobe failures.
type KprobeIgnore struct {
	CallNotFound bool `yaml:"callNotFound,omitempty"`
}

// KprobeArg defines an argument to extract from a kprobe.
type KprobeArg struct {
	Index int    `yaml:"index"`
	Type  string `yaml:"type"`
}

// SelectorSpec defines filtering selectors for a kprobe.
type SelectorSpec struct {
	MatchArgs    []MatchArgSpec    `yaml:"matchArgs,omitempty"`
	MatchActions []MatchActionSpec `yaml:"matchActions"`
}

// MatchArgSpec defines argument-based filtering.
type MatchArgSpec struct {
	Index    int      `yaml:"index"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values"`
}

// MatchActionSpec defines the action to take when a selector matches.
type MatchActionSpec struct {
	Action string `yaml:"action"`
}

// EventType represents the host-side event type a kprobe maps to.
type EventType string

const (
	EventTypeFile     EventType = "file"
	EventTypeNetwork  EventType = "net"
	EventTypeSecurity EventType = "security"
)

// CuratedKprobe holds a kprobe definition along with its event parser metadata.
type CuratedKprobe struct {
	Spec      KprobeSpec
	EventType EventType
	Op        string // operation name for structured event parsing
}

// defaultOrder defines the canonical ordering of default kprobes.
var defaultOrder = []string{
	"security_file_open",
	"vfs_unlink",
	"vfs_rename",
	"security_socket_connect",
	"inet_csk_listen_start",
}

// Registry maps kernel function names to their curated kprobe definitions.
var Registry = map[string]CuratedKprobe{
	"security_file_open": {
		Spec: KprobeSpec{
			Call: "security_file_open",
			Args: []KprobeArg{{Index: 0, Type: "file"}},
			Selectors: []SelectorSpec{{
				MatchArgs: []MatchArgSpec{{
					Index:    0,
					Operator: "NotPrefix",
					Values:   []string{"/dev/vport", "/var/log/tetragon/", "/proc/", "/sys/"},
				}},
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeFile,
		Op:        "open",
	},
	"vfs_unlink": {
		Spec: KprobeSpec{
			Call: "vfs_unlink",
			Args: []KprobeArg{{Index: 2, Type: "file"}},
			Selectors: []SelectorSpec{{
				MatchArgs: []MatchArgSpec{{
					Index:    2,
					Operator: "NotPrefix",
					Values:   []string{"/proc/", "/sys/"},
				}},
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeFile,
		Op:        "delete",
	},
	"vfs_rename": {
		Spec: KprobeSpec{
			Call: "vfs_rename",
			Args: []KprobeArg{
				{Index: 1, Type: "file"},
				{Index: 3, Type: "file"},
			},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeFile,
		Op:        "rename",
	},
	"security_socket_connect": {
		Spec: KprobeSpec{
			Call: "security_socket_connect",
			Args: []KprobeArg{{Index: 1, Type: "sockaddr"}},
			Selectors: []SelectorSpec{{
				MatchArgs: []MatchArgSpec{{
					Index:    1,
					Operator: "Family",
					Values:   []string{"AF_INET", "AF_INET6"},
				}},
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeNetwork,
		Op:        "connect",
	},
	"inet_csk_listen_start": {
		Spec: KprobeSpec{
			Call: "inet_csk_listen_start",
			Args: []KprobeArg{{Index: 0, Type: "sock"}},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeNetwork,
		Op:        "listen",
	},

	// --- Security monitoring (opt-in) ---

	"security_bprm_check": {
		Spec: KprobeSpec{
			Call: "security_bprm_check",
			Args: []KprobeArg{{Index: 0, Type: "linux_binprm"}},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeSecurity,
		Op:        "exec_check",
	},
	"commit_creds": {
		Spec: KprobeSpec{
			Call: "commit_creds",
			Args: []KprobeArg{{Index: 0, Type: "cred"}},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeSecurity,
		Op:        "cred_change",
	},
	"do_init_module": {
		Spec: KprobeSpec{
			Call: "do_init_module",
			Args: []KprobeArg{{Index: 0, Type: "module"}},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeSecurity,
		Op:        "module_load",
	},
	"sys_setuid": {
		Spec: KprobeSpec{
			Call:    "sys_setuid",
			Syscall: true,
			Args:    []KprobeArg{{Index: 0, Type: "int"}},
			Selectors: []SelectorSpec{{
				MatchArgs: []MatchArgSpec{{
					Index:    0,
					Operator: "Equal",
					Values:   []string{"0"},
				}},
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeSecurity,
		Op:        "setuid_root",
	},

	// --- Behavioral monitoring (opt-in) ---

	"sys_ptrace": {
		Spec: KprobeSpec{
			Call:    "sys_ptrace",
			Syscall: true,
			Args:    []KprobeArg{{Index: 0, Type: "int"}},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeSecurity,
		Op:        "ptrace",
	},
	"path_mount": {
		Spec: KprobeSpec{
			Call: "path_mount",
			Args: []KprobeArg{
				{Index: 0, Type: "string"},
				{Index: 1, Type: "path"},
				{Index: 2, Type: "string"},
			},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeSecurity,
		Op:        "mount",
	},

	// --- Additional network (opt-in) ---

	"tcp_close": {
		Spec: KprobeSpec{
			Call: "tcp_close",
			Args: []KprobeArg{{Index: 0, Type: "sock"}},
			Selectors: []SelectorSpec{{
				MatchActions: []MatchActionSpec{{Action: "Post"}},
			}},
		},
		EventType: EventTypeNetwork,
		Op:        "close",
	},
}

// DefaultKprobeNames returns the ordered list of all default kprobe function names.
func DefaultKprobeNames() []string {
	return slices.Clone(defaultOrder)
}

// AllKprobeNames returns all valid curated kprobe names, sorted alphabetically.
func AllKprobeNames() []string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidKprobe returns true if name is a valid curated kprobe.
func ValidKprobe(name string) bool {
	_, ok := Registry[name]
	return ok
}

// RenderPolicy generates a Tetragon TracingPolicy YAML from the given kprobe names.
// If names is nil, all default kprobes are included.
// If names is empty (non-nil), returns nil (no policy to write).
// Returns an error if any name is not in the registry.
func RenderPolicy(names []string) ([]byte, error) {
	if names != nil && len(names) == 0 {
		return nil, nil
	}

	if names == nil {
		names = defaultOrder
	}

	specs := make([]KprobeSpec, 0, len(names))
	for _, name := range names {
		curated, ok := Registry[name]
		if !ok {
			return nil, fmt.Errorf("unknown kprobe %q; valid kprobes: %v", name, AllKprobeNames())
		}
		spec := curated.Spec
		spec.Ignore = &KprobeIgnore{CallNotFound: true}
		specs = append(specs, spec)
	}

	policy := TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata:   TracingPolicyMeta{Name: "abox-monitor"},
		Spec:       TracingPolicySpec{Kprobes: specs},
	}

	return yaml.Marshal(&policy)
}

// RenderPerKrobePolicies generates one TracingPolicy YAML per kprobe.
// Returns a map of filename → YAML content.
// Isolating kprobes in separate policies prevents one broken kprobe from
// blocking all others (Tetragon fails the entire policy if any kprobe
// attachment fails).
func RenderPerKrobePolicies(names []string) (map[string][]byte, error) {
	if names == nil {
		names = defaultOrder
	}
	if len(names) == 0 {
		return nil, nil //nolint:nilnil // nil means no policies to render
	}

	result := make(map[string][]byte, len(names))
	for _, name := range names {
		curated, ok := Registry[name]
		if !ok {
			return nil, fmt.Errorf("unknown kprobe %q; valid kprobes: %v", name, AllKprobeNames())
		}
		spec := curated.Spec
		spec.Ignore = &KprobeIgnore{CallNotFound: true}

		p := TracingPolicy{
			APIVersion: "cilium.io/v1alpha1",
			Kind:       "TracingPolicy",
			Metadata:   TracingPolicyMeta{Name: "abox-" + strings.ReplaceAll(name, "_", "-")},
			Spec:       TracingPolicySpec{Kprobes: []KprobeSpec{spec}},
		}

		data, err := yaml.Marshal(&p)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal policy for %s: %w", name, err)
		}
		result[fmt.Sprintf("abox-kprobe-%s.yaml", name)] = data
	}
	return result, nil
}
