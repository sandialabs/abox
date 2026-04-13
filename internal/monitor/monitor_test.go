package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/tetragon/policy"
)

func TestParseTetragonEvent(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantNil bool
		want    EventType
	}{
		{
			name: "process exec event",
			data: `{"process_exec":{"process":{"pid":1234,"binary":"/usr/bin/ls","arguments":"-la","cwd":"/home/user"}}}`,
			want: EventTypeExec,
		},
		{
			name: "kprobe file event",
			data: `{"process_kprobe":{"function_name":"security_file_open","process":{"pid":1234},"args":[{"file_arg":{"path":"/etc/passwd"}}]}}`,
			want: EventTypeFile,
		},
		{
			name: "kprobe network event (sockaddr)",
			data: `{"process_kprobe":{"function_name":"security_socket_connect","process":{"pid":1234},"args":[{"sockaddr_arg":{"family":"AF_INET","addr":"93.184.216.34","port":443}}]}}`,
			want: EventTypeNetwork,
		},
		{
			name: "kprobe network event (sock)",
			data: `{"process_kprobe":{"function_name":"tcp_close","process":{"pid":1234},"args":[{"sock_arg":{"daddr":"93.184.216.34","dport":443,"protocol":"TCP"}}]}}`,
			want: EventTypeNetwork,
		},
		{
			name:    "process exit event (skipped)",
			data:    `{"process_exit":{"process":{"pid":1234}}}`,
			wantNil: true,
		},
		{
			name: "invalid json",
			data: `not json`,
			want: EventTypeUnknown, // Should error but we check for nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := ParseTetragonEvent([]byte(tt.data))
			if tt.name == "invalid json" {
				if err == nil {
					t.Error("ParseTetragonEvent() expected error for invalid JSON")
				}
				return
			}
			if tt.wantNil {
				if event != nil {
					t.Errorf("ParseTetragonEvent() = %v, want nil", event)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTetragonEvent() error = %v", err)
			}
			if event.Type != tt.want {
				t.Errorf("ParseTetragonEvent().Type = %v, want %v", event.Type, tt.want)
			}
		})
	}
}

func TestExtractComm(t *testing.T) {
	tests := []struct {
		binary string
		want   string
	}{
		{"/usr/bin/ls", "ls"},
		{"/bin/bash", "bash"},
		{"ls", "ls"},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractComm(tt.binary)
		if got != tt.want {
			t.Errorf("extractComm(%q) = %q, want %q", tt.binary, got, tt.want)
		}
	}
}

func TestRegistryKprobeOps(t *testing.T) {
	tests := []struct {
		funcName string
		wantOp   string
	}{
		{"security_file_open", "open"},
		{"vfs_unlink", "delete"},
		{"vfs_rename", "rename"},
		{"security_socket_connect", "connect"},
		{"inet_csk_listen_start", "listen"},
		{"security_bprm_check", "exec_check"},
		{"commit_creds", "cred_change"},
		{"do_init_module", "module_load"},
		{"sys_setuid", "setuid_root"},
		{"sys_ptrace", "ptrace"},
		{"path_mount", "mount"},
		{"tcp_close", "close"},
	}

	for _, tt := range tests {
		curated, ok := policy.Registry[tt.funcName]
		if !ok {
			t.Errorf("kprobe %q not found in registry", tt.funcName)
			continue
		}
		if curated.Op != tt.wantOp {
			t.Errorf("Registry[%q].Op = %q, want %q", tt.funcName, curated.Op, tt.wantOp)
		}
	}
}

func TestParseUnknownKprobe(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":42,"binary":"/usr/bin/test"},"function_name":"custom_unknown_hook","args":[{"file_arg":{"path":"/usr/bin/test"}}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeKprobe {
		t.Errorf("expected EventTypeKprobe, got %s", event.Type)
	}
	if event.Op != "custom_unknown_hook" {
		t.Errorf("expected Op=custom_unknown_hook, got %s", event.Op)
	}
	if event.Args != "/usr/bin/test" {
		t.Errorf("expected Args=/usr/bin/test, got %s", event.Args)
	}
	if event.PID != 42 {
		t.Errorf("expected PID=42, got %d", event.PID)
	}
}

func TestParseUnknownKprobeWithSockArg(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":99,"binary":"/usr/bin/nc"},"function_name":"custom_sock_hook","args":[{"sock_arg":{"saddr":"10.0.0.1","sport":12345,"daddr":"10.0.0.2","dport":80}}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeKprobe {
		t.Errorf("expected EventTypeKprobe, got %s", event.Type)
	}
	if event.Op != "custom_sock_hook" {
		t.Errorf("expected Op=custom_sock_hook, got %s", event.Op)
	}
	if event.Args != "10.0.0.1:12345->10.0.0.2:80" {
		t.Errorf("expected formatted sock arg, got %s", event.Args)
	}
}

func TestParseSecurityBprmCheck(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":42,"binary":"/usr/bin/bash"},"function_name":"security_bprm_check","args":[{"linux_binprm_arg":{"path":"/usr/bin/curl"}}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeSecurity {
		t.Errorf("expected EventTypeSecurity, got %s", event.Type)
	}
	if event.Op != "exec_check" {
		t.Errorf("expected Op=exec_check, got %s", event.Op)
	}
	if event.Path != "/usr/bin/curl" {
		t.Errorf("expected Path=/usr/bin/curl, got %s", event.Path)
	}
}

func TestParseCommitCreds(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":100,"binary":"/usr/bin/su"},"function_name":"commit_creds","args":[{"process_credentials_arg":{"uid":0,"gid":0,"euid":0,"egid":0}}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeSecurity {
		t.Errorf("expected EventTypeSecurity, got %s", event.Type)
	}
	if event.Op != "cred_change" {
		t.Errorf("expected Op=cred_change, got %s", event.Op)
	}
	if !strings.Contains(event.Args, "euid=0") {
		t.Errorf("expected euid=0 in args, got %s", event.Args)
	}
}

func TestParseDoInitModule(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":1,"binary":"/sbin/modprobe"},"function_name":"do_init_module","args":[{"module_arg":{"name":"nf_tables"}}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeSecurity {
		t.Errorf("expected EventTypeSecurity, got %s", event.Type)
	}
	if event.Op != "module_load" {
		t.Errorf("expected Op=module_load, got %s", event.Op)
	}
	if event.Args != "nf_tables" {
		t.Errorf("expected Args=nf_tables, got %s", event.Args)
	}
}

func TestParseSysSetuid(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":200,"binary":"/usr/bin/sudo"},"function_name":"sys_setuid","args":[{"int_arg":0}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeSecurity {
		t.Errorf("expected EventTypeSecurity, got %s", event.Type)
	}
	if event.Op != "setuid_root" {
		t.Errorf("expected Op=setuid_root, got %s", event.Op)
	}
	if event.Args != "0" {
		t.Errorf("expected Args=0, got %s", event.Args)
	}
}

func TestParseArchPrefixedSysSetuid(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":200,"binary":"/usr/bin/sudo"},"function_name":"__x64_sys_setuid","args":[{"int_arg":0}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeSecurity {
		t.Errorf("expected EventTypeSecurity, got %s", event.Type)
	}
	if event.Op != "setuid_root" {
		t.Errorf("expected Op=setuid_root, got %s", event.Op)
	}
	if event.RawType != "__x64_sys_setuid" {
		t.Errorf("expected RawType=__x64_sys_setuid, got %s", event.RawType)
	}
}

func TestParseSysPtrace(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":300,"binary":"/usr/bin/strace"},"function_name":"sys_ptrace","args":[{"int_arg":16}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeSecurity {
		t.Errorf("expected EventTypeSecurity, got %s", event.Type)
	}
	if event.Op != "ptrace" {
		t.Errorf("expected Op=ptrace, got %s", event.Op)
	}
	if event.Args != "16" {
		t.Errorf("expected Args=16, got %s", event.Args)
	}
}

func TestParsePathMount(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":1,"binary":"/usr/bin/mount"},"function_name":"path_mount","args":[{"string_arg":"/dev/sda1"},{"file_arg":{"path":"/mnt"}},{"string_arg":"ext4"}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeSecurity {
		t.Errorf("expected EventTypeSecurity, got %s", event.Type)
	}
	if event.Op != "mount" {
		t.Errorf("expected Op=mount, got %s", event.Op)
	}
	if event.Args != "/dev/sda1 /mnt ext4" {
		t.Errorf("expected Args='/dev/sda1 /mnt ext4', got %s", event.Args)
	}
}

func TestParseTcpClose(t *testing.T) {
	raw := `{"process_kprobe":{"process":{"pid":500,"binary":"/usr/bin/curl"},"function_name":"tcp_close","args":[{"sock_arg":{"daddr":"10.0.0.1","dport":443,"protocol":"TCP"}}]},"time":"2025-01-01T00:00:00Z"}`
	event, err := ParseTetragonEvent([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Type != EventTypeNetwork {
		t.Errorf("expected EventTypeNetwork, got %s", event.Type)
	}
	if event.Op != "close" {
		t.Errorf("expected Op=close, got %s", event.Op)
	}
	if event.Dest != "10.0.0.1:443" {
		t.Errorf("expected Dest=10.0.0.1:443, got %s", event.Dest)
	}
}

// --- CloudInitContributor tests ---

func TestCloudInitContributorDisabled(t *testing.T) {
	c := &CloudInitContributor{Enabled: false}
	contrib, err := c.Contribute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contrib != nil {
		t.Fatal("expected nil contribution when disabled")
	}
}

func TestCloudInitContributorDefaultKprobes(t *testing.T) {
	c := &CloudInitContributor{
		Enabled:         true,
		Kprobes:         nil, // nil = all defaults
		TetragonTarball: "/tmp/fake-tarball.tar.gz",
		TetragonVersion: "v1.3.0",
	}
	contrib, err := c.Contribute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contrib == nil {
		t.Fatal("expected non-nil contribution")
		return
	}

	// Should have write_files for: monitor script, service, and policy
	if len(contrib.WriteFiles) < 3 {
		t.Fatalf("expected at least 3 write_files entries, got %d", len(contrib.WriteFiles))
	}

	// Check monitor agent script is present
	if !strings.Contains(contrib.WriteFiles[0], "/usr/local/bin/abox-monitor-agent") {
		t.Error("expected monitor agent script in write_files[0]")
	}

	// Check service file is present
	if !strings.Contains(contrib.WriteFiles[1], "/etc/systemd/system/abox-monitor.service") {
		t.Error("expected systemd service in write_files[1]")
	}

	// Check per-kprobe policies are generated (one per default kprobe)
	// write_files[0] = monitor agent, [1] = service, [2] = kprobe_multi config, [3] = rb-size-total, [4..] = per-kprobe policies
	defaultNames := policy.DefaultKprobeNames()
	expectedEntries := 4 + len(defaultNames)
	if len(contrib.WriteFiles) != expectedEntries {
		t.Fatalf("expected %d write_files entries, got %d", expectedEntries, len(contrib.WriteFiles))
	}

	// All default kprobes should have per-kprobe policy files
	allWriteFiles := strings.Join(contrib.WriteFiles, "\n")
	for _, name := range defaultNames {
		if !strings.Contains(allWriteFiles, "abox-kprobe-"+name+".yaml") {
			t.Errorf("expected per-kprobe policy file for %q", name)
		}
	}

	// Check runcmd entries
	if len(contrib.Runcmd) == 0 {
		t.Fatal("expected runcmd entries")
	}

	// Version should appear in runcmd
	found := false
	for _, cmd := range contrib.Runcmd {
		if strings.Contains(cmd, "v1.3.0") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TetragonVersion in runcmd")
	}

	// ISO files should include tarball
	if contrib.ISOFiles["tetragon.tar.gz"] != "/tmp/fake-tarball.tar.gz" {
		t.Errorf("expected tarball in ISOFiles, got %v", contrib.ISOFiles)
	}
}

func TestCloudInitContributorKprobeSubset(t *testing.T) {
	c := &CloudInitContributor{
		Enabled:         true,
		Kprobes:         []string{"security_socket_connect"},
		TetragonTarball: "/tmp/fake.tar.gz",
		TetragonVersion: "v1.3.0",
	}
	contrib, err := c.Contribute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contrib == nil {
		t.Fatal("expected non-nil contribution")
		return
	}

	// Should have exactly 5 write_files: agent, service, kprobe_multi config, rb-size-total, one kprobe policy
	if len(contrib.WriteFiles) != 5 {
		t.Fatalf("expected 5 write_files entries, got %d", len(contrib.WriteFiles))
	}
	// Policy should contain security_socket_connect but not other kprobes
	policyEntry := contrib.WriteFiles[4]
	if !strings.Contains(policyEntry, "security_socket_connect") {
		t.Error("expected security_socket_connect in policy")
	}
	if strings.Contains(policyEntry, "security_file_open") {
		t.Error("expected security_file_open to be absent from subset policy")
	}
}

func TestCloudInitContributorCustomPolicies(t *testing.T) {
	// Create temp policy files
	tmpDir := t.TempDir()
	policyContent := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\n"
	policyPath := filepath.Join(tmpDir, "custom.yaml")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &CloudInitContributor{
		Enabled:         true,
		Policies:        []string{policyPath},
		TetragonTarball: "/tmp/fake.tar.gz",
		TetragonVersion: "v1.3.0",
	}
	contrib, err := c.Contribute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contrib == nil {
		t.Fatal("expected non-nil contribution")
		return
	}

	// Should have custom policy in write_files (after script + service + kprobe_multi config + rb-size-total)
	if len(contrib.WriteFiles) < 5 {
		t.Fatalf("expected at least 5 write_files, got %d", len(contrib.WriteFiles))
	}
	if !strings.Contains(contrib.WriteFiles[4], "custom-0.yaml") {
		t.Error("expected custom-0.yaml path in write_files")
	}
	if !strings.Contains(contrib.WriteFiles[4], "TracingPolicy") {
		t.Error("expected policy content embedded in write_files")
	}
}

func TestCloudInitContributorInvalidVersion(t *testing.T) {
	c := &CloudInitContributor{
		Enabled:         true,
		TetragonVersion: "malicious; rm -rf /",
		TetragonTarball: "/tmp/fake.tar.gz",
	}
	_, err := c.Contribute()
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestCloudInitContributorMissingPolicyFile(t *testing.T) {
	c := &CloudInitContributor{
		Enabled:         true,
		Policies:        []string{"/nonexistent/policy.yaml"},
		TetragonTarball: "/tmp/fake.tar.gz",
		TetragonVersion: "v1.3.0",
	}
	_, err := c.Contribute()
	if err == nil {
		t.Fatal("expected error for missing policy file")
	}
	if !strings.Contains(err.Error(), "failed to read monitor policy") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCloudInitContributorKprobeMultiEnabled(t *testing.T) {
	c := &CloudInitContributor{
		Enabled:         true,
		KprobeMulti:     true,
		Kprobes:         []string{"security_socket_connect"},
		TetragonTarball: "/tmp/fake.tar.gz",
		TetragonVersion: "v1.3.0",
	}
	contrib, err := c.Contribute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contrib == nil {
		t.Fatal("expected non-nil contribution")
		return
	}

	// When KprobeMulti is true, the disable-kprobe-multi config drop-in should NOT be present
	for _, wf := range contrib.WriteFiles {
		if strings.Contains(wf, "disable-kprobe-multi") {
			t.Error("expected no disable-kprobe-multi config drop-in when KprobeMulti is true")
		}
	}

	// Should have exactly 4 write_files: agent, service, rb-size-total, one kprobe policy (no kprobe_multi drop-in)
	if len(contrib.WriteFiles) != 4 {
		t.Fatalf("expected 4 write_files entries, got %d", len(contrib.WriteFiles))
	}
}
