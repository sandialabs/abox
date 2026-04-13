package policy

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestDefaultKprobeNames(t *testing.T) {
	names := DefaultKprobeNames()
	if len(names) != 5 {
		t.Fatalf("expected 5 default kprobes, got %d", len(names))
	}
	// Verify all defaults are in the registry
	for _, name := range names {
		if !ValidKprobe(name) {
			t.Errorf("default kprobe %q not in registry", name)
		}
	}
}

func TestAllKprobeNames(t *testing.T) {
	names := AllKprobeNames()
	if len(names) != len(Registry) {
		t.Fatalf("expected %d names, got %d", len(Registry), len(names))
	}
	// Verify sorted
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("names not sorted: %q comes after %q", names[i], names[i-1])
		}
	}
}

func TestValidKprobe(t *testing.T) {
	valid := []string{
		"security_socket_connect", "security_file_open", "vfs_unlink", "vfs_rename", "inet_csk_listen_start",
		"security_bprm_check", "commit_creds", "do_init_module", "sys_setuid",
		"sys_ptrace", "path_mount", "tcp_close",
	}
	for _, name := range valid {
		if !ValidKprobe(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	if ValidKprobe("nonexistent_kprobe") {
		t.Error("expected nonexistent_kprobe to be invalid")
	}
}

func TestRenderPolicyNilDefaults(t *testing.T) {
	data, err := RenderPolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil output for nil names")
	}

	// Verify valid YAML
	var policy TracingPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}

	if policy.APIVersion != "cilium.io/v1alpha1" {
		t.Errorf("unexpected apiVersion: %s", policy.APIVersion)
	}
	if policy.Kind != "TracingPolicy" {
		t.Errorf("unexpected kind: %s", policy.Kind)
	}
	if policy.Metadata.Name != "abox-monitor" {
		t.Errorf("unexpected name: %s", policy.Metadata.Name)
	}
	if len(policy.Spec.Kprobes) != 5 {
		t.Errorf("expected 5 kprobes, got %d", len(policy.Spec.Kprobes))
	}

	// Verify all default kprobes are present
	calls := make(map[string]bool)
	for _, kp := range policy.Spec.Kprobes {
		calls[kp.Call] = true
	}
	for _, name := range DefaultKprobeNames() {
		if !calls[name] {
			t.Errorf("missing default kprobe %q in output", name)
		}
	}
}

func TestRenderPolicySyscallOmitempty(t *testing.T) {
	// Non-syscall kprobes should have explicit "syscall: false" in YAML output
	data, err := RenderPolicy([]string{"security_socket_connect"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "syscall: false") {
		t.Errorf("non-syscall kprobe should have syscall: false, got:\n%s", data)
	}

	// Syscall kprobes should have "syscall: true"
	data, err = RenderPolicy([]string{"sys_ptrace"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "syscall: true") {
		t.Errorf("syscall kprobe should have syscall: true, got:\n%s", data)
	}
}

func TestRenderPolicyIgnoreCallNotFound(t *testing.T) {
	data, err := RenderPolicy([]string{"security_socket_connect"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "callNotFound: true") {
		t.Errorf("rendered policy should include ignore.callNotFound, got:\n%s", data)
	}
}

func TestRenderPolicySubset(t *testing.T) {
	data, err := RenderPolicy([]string{"security_socket_connect", "vfs_unlink"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var policy TracingPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}

	if len(policy.Spec.Kprobes) != 2 {
		t.Fatalf("expected 2 kprobes, got %d", len(policy.Spec.Kprobes))
	}
	if policy.Spec.Kprobes[0].Call != "security_socket_connect" {
		t.Errorf("expected first kprobe to be security_socket_connect, got %s", policy.Spec.Kprobes[0].Call)
	}
	if policy.Spec.Kprobes[1].Call != "vfs_unlink" {
		t.Errorf("expected second kprobe to be vfs_unlink, got %s", policy.Spec.Kprobes[1].Call)
	}
}

func TestRenderPolicyEmptyList(t *testing.T) {
	data, err := RenderPolicy([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil output for empty names, got %d bytes", len(data))
	}
}

func TestRenderPolicyInvalidName(t *testing.T) {
	_, err := RenderPolicy([]string{"security_socket_connect", "bogus_kprobe"})
	if err == nil {
		t.Fatal("expected error for invalid kprobe name")
	}
	if !strings.Contains(err.Error(), "bogus_kprobe") {
		t.Errorf("error should mention invalid name, got: %v", err)
	}
}

func TestRenderPolicyNewKprobes(t *testing.T) {
	names := []string{"security_bprm_check", "commit_creds", "do_init_module", "sys_setuid", "sys_ptrace", "path_mount", "tcp_close"}
	data, err := RenderPolicy(names)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var policy TracingPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}

	if len(policy.Spec.Kprobes) != len(names) {
		t.Fatalf("expected %d kprobes, got %d", len(names), len(policy.Spec.Kprobes))
	}

	// Verify syscall flag is set correctly
	for _, kp := range policy.Spec.Kprobes {
		curated := Registry[kp.Call]
		if kp.Syscall != curated.Spec.Syscall {
			t.Errorf("kprobe %q: syscall=%v, want %v", kp.Call, kp.Syscall, curated.Spec.Syscall)
		}
	}

	// sys_setuid should have matchArgs filter for uid=0
	for _, kp := range policy.Spec.Kprobes {
		if kp.Call == "sys_setuid" {
			if len(kp.Selectors) != 1 || len(kp.Selectors[0].MatchArgs) != 1 {
				t.Error("sys_setuid should have matchArgs selector")
			} else if kp.Selectors[0].MatchArgs[0].Operator != "Equal" {
				t.Errorf("sys_setuid matchArgs operator = %q, want Equal", kp.Selectors[0].MatchArgs[0].Operator)
			}
		}
	}

	// path_mount should have 3 args: string, path, string
	for _, kp := range policy.Spec.Kprobes {
		if kp.Call == "path_mount" {
			if len(kp.Args) != 3 {
				t.Errorf("path_mount args count = %d, want 3", len(kp.Args))
			}
			wantTypes := []string{"string", "path", "string"}
			for i, arg := range kp.Args {
				if i < len(wantTypes) && arg.Type != wantTypes[i] {
					t.Errorf("path_mount arg[%d].Type = %q, want %q", i, arg.Type, wantTypes[i])
				}
			}
		}
	}
}

func TestRenderPerKrobePolicies(t *testing.T) {
	names := []string{"security_socket_connect", "vfs_unlink"}
	policies, err := RenderPerKrobePolicies(names)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}

	// Verify each policy has exactly one kprobe
	for filename, data := range policies {
		var p TracingPolicy
		if err := yaml.Unmarshal(data, &p); err != nil {
			t.Fatalf("policy %s is not valid YAML: %v", filename, err)
		}
		if len(p.Spec.Kprobes) != 1 {
			t.Errorf("policy %s: expected 1 kprobe, got %d", filename, len(p.Spec.Kprobes))
		}
		if p.Spec.Kprobes[0].Ignore == nil || !p.Spec.Kprobes[0].Ignore.CallNotFound {
			t.Errorf("policy %s: expected ignore.callNotFound: true", filename)
		}
		if strings.Contains(p.Metadata.Name, "_") {
			t.Errorf("policy %s: metadata.name %q contains underscores (RFC 1123 violation)", filename, p.Metadata.Name)
		}
	}

	// Verify filenames
	if _, ok := policies["abox-kprobe-security_socket_connect.yaml"]; !ok {
		t.Error("missing abox-kprobe-security_socket_connect.yaml")
	}
	if _, ok := policies["abox-kprobe-vfs_unlink.yaml"]; !ok {
		t.Error("missing abox-kprobe-vfs_unlink.yaml")
	}
}

func TestRenderPerKrobePoliciesDefaults(t *testing.T) {
	policies, err := RenderPerKrobePolicies(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 5 {
		t.Fatalf("expected 5 default policies, got %d", len(policies))
	}
}

func TestRenderPerKrobePoliciesEmpty(t *testing.T) {
	policies, err := RenderPerKrobePolicies([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policies != nil {
		t.Errorf("expected nil for empty names, got %d policies", len(policies))
	}
}

func TestRenderPolicySelectorsPreserved(t *testing.T) {
	data, err := RenderPolicy([]string{"security_file_open"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var policy TracingPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}

	kp := policy.Spec.Kprobes[0]
	if len(kp.Selectors) != 1 {
		t.Fatalf("expected 1 selector, got %d", len(kp.Selectors))
	}
	sel := kp.Selectors[0]
	if len(sel.MatchArgs) != 1 {
		t.Fatalf("expected 1 matchArgs, got %d", len(sel.MatchArgs))
	}
	if sel.MatchArgs[0].Operator != "NotPrefix" {
		t.Errorf("expected NotPrefix operator, got %s", sel.MatchArgs[0].Operator)
	}
	if len(sel.MatchArgs[0].Values) != 4 {
		t.Errorf("expected 4 filter values for security_file_open, got %d", len(sel.MatchArgs[0].Values))
	}
}
