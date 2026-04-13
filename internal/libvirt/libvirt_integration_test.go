package libvirt

import (
	"errors"
	"strings"
	"testing"
)

func TestNetworkExists_WithMock(t *testing.T) {
	mock := &MockCommander{
		RunFunc: func(name string, args ...string) (string, error) {
			// Args now include -c qemu:///system prefix
			if name == "virsh" && len(args) >= 3 && args[2] == "net-list" {
				return "abox-test\nabox-other\n", nil
			}
			return "", nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	tests := []struct {
		name     string
		network  string
		expected bool
	}{
		{"exists", "abox-test", true},
		{"exists-other", "abox-other", true},
		{"not-exists", "abox-missing", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NetworkExists(tt.network)
			if result != tt.expected {
				t.Errorf("NetworkExists(%q) = %v, want %v", tt.network, result, tt.expected)
			}
		})
	}
}

func TestDomainExists_WithMock(t *testing.T) {
	mock := &MockCommander{
		RunFunc: func(name string, args ...string) (string, error) {
			// Args now include -c qemu:///system prefix
			if name == "virsh" && len(args) >= 3 && args[2] == "list" {
				return "abox-test\nabox-dev\n", nil
			}
			return "", nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	if !DomainExists("abox-test") {
		t.Error("DomainExists(abox-test) should be true")
	}
	if DomainExists("abox-missing") {
		t.Error("DomainExists(abox-missing) should be false")
	}
}

func TestDomainState_WithMock(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		err      error
		expected string
	}{
		{"running", "running\n", nil, "running"},
		{"shut-off", "shut off\n", nil, "shut off"},
		{"error", "", errors.New("domain not found"), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockCommander{
				RunFunc: func(name string, args ...string) (string, error) {
					return tt.output, tt.err
				},
			}
			prev := SetCommander(mock)
			defer SetCommander(prev)

			result := DomainState("test-domain")
			if result != tt.expected {
				t.Errorf("DomainState() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestDomainIsRunning_WithMock(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected bool
	}{
		{"running", "running\n", true},
		{"shut-off", "shut off\n", false},
		{"paused", "paused\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockCommander{
				RunFunc: func(name string, args ...string) (string, error) {
					return tt.output, nil
				},
			}
			prev := SetCommander(mock)
			defer SetCommander(prev)

			result := DomainIsRunning("test-domain")
			if result != tt.expected {
				t.Errorf("DomainIsRunning() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetDomainIP_WithMock(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		err       error
		wantIP    string
		wantError bool
	}{
		{
			name:   "agent-success",
			output: "eth0      52:54:00:ab:cd:ef    ipv4         10.10.10.2/24\n",
			wantIP: "10.10.10.2",
		},
		{
			name:      "no-ip",
			output:    "",
			wantError: true,
		},
		{
			name:   "skip-loopback",
			output: "lo        00:00:00:00:00:00    ipv4         127.0.0.1/8\neth0      52:54:00:ab:cd:ef    ipv4         10.10.10.2/24\n",
			wantIP: "10.10.10.2",
		},
		{
			name:      "skip-header-row",
			output:    "Name       MAC address          Protocol     Address\neth0       52:54:00:ab:cd:ef    ipv4         10.10.10.2/24\n",
			wantIP:    "10.10.10.2",
			wantError: false,
		},
		{
			name:      "header-only",
			output:    "Name       MAC address          Protocol     Address\n",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockCommander{
				RunFunc: func(name string, args ...string) (string, error) {
					if tt.err != nil {
						return "", tt.err
					}
					return tt.output, nil
				},
			}
			prev := SetCommander(mock)
			defer SetCommander(prev)

			ip, err := GetDomainIP("test-domain")
			if tt.wantError {
				if err == nil {
					t.Error("GetDomainIP() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("GetDomainIP() error = %v", err)
				return
			}
			if ip != tt.wantIP {
				t.Errorf("GetDomainIP() = %q, want %q", ip, tt.wantIP)
			}
		})
	}
}

func TestListSnapshots_WithMock(t *testing.T) {
	mock := &MockCommander{
		RunFunc: func(name string, args ...string) (string, error) {
			if strings.Contains(strings.Join(args, " "), "snapshot-list") && strings.Contains(strings.Join(args, " "), "--name") {
				return "snap1\nsnap2\n", nil
			}
			if strings.Contains(strings.Join(args, " "), "snapshot-info") {
				snapName := args[len(args)-1]
				return "Name:           " + snapName + "\nCreation Time:  2024-01-15 10:30:00\nState:          running\nCurrent:        yes\n", nil
			}
			return "", nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	snapshots, err := ListSnapshots("test-domain")
	if err != nil {
		t.Fatalf("ListSnapshots() error = %v", err)
	}

	if len(snapshots) != 2 {
		t.Errorf("ListSnapshots() returned %d snapshots, want 2", len(snapshots))
	}

	if snapshots[0].Name != "snap1" {
		t.Errorf("snapshots[0].Name = %q, want %q", snapshots[0].Name, "snap1")
	}
}

func TestDefineNetwork_WithMock(t *testing.T) {
	var capturedStdin string
	mock := &MockCommander{
		RunWithStdinFunc: func(name string, stdin string, args ...string) error {
			capturedStdin = stdin
			return nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := DefineNetwork("<network>test</network>")
	if err != nil {
		t.Errorf("DefineNetwork() error = %v", err)
	}

	if capturedStdin != "<network>test</network>" {
		t.Errorf("DefineNetwork() stdin = %q, want %q", capturedStdin, "<network>test</network>")
	}

	if len(mock.Calls) != 1 {
		t.Fatalf("DefineNetwork() made %d calls, want 1", len(mock.Calls))
	}

	call := mock.Calls[0]
	if call.Name != "virsh" {
		t.Errorf("DefineNetwork() called %q, want %q", call.Name, "virsh")
	}
	// Args are: -c, qemu:///system, net-define, /dev/stdin
	if len(call.Args) < 3 || call.Args[2] != "net-define" {
		t.Errorf("DefineNetwork() args = %v, want [..., net-define, ...]", call.Args)
	}
}

func TestDefineDomain_WithMock(t *testing.T) {
	var capturedStdin string
	mock := &MockCommander{
		RunWithStdinFunc: func(name string, stdin string, args ...string) error {
			capturedStdin = stdin
			return nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := DefineDomain("<domain>test</domain>")
	if err != nil {
		t.Errorf("DefineDomain() error = %v", err)
	}

	if capturedStdin != "<domain>test</domain>" {
		t.Errorf("DefineDomain() stdin = %q, want %q", capturedStdin, "<domain>test</domain>")
	}
}

func TestStartNetwork_WithMock(t *testing.T) {
	mock := &MockCommander{
		RunFunc: func(name string, args ...string) (string, error) {
			return "", nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := StartNetwork("abox-test")
	if err != nil {
		t.Errorf("StartNetwork() error = %v", err)
	}

	if len(mock.Calls) != 1 {
		t.Fatalf("StartNetwork() made %d calls, want 1", len(mock.Calls))
	}

	call := mock.Calls[0]
	// Args are: -c, qemu:///system, net-start, abox-test
	if call.Name != "virsh" || len(call.Args) < 4 || call.Args[2] != "net-start" || call.Args[3] != "abox-test" {
		t.Errorf("StartNetwork() called %v %v, want virsh -c qemu:///system net-start abox-test", call.Name, call.Args)
	}
}

func TestApplyNWFilter_WithMock(t *testing.T) {
	var capturedStdin string
	mock := &MockCommander{
		RunWithStdinFunc: func(name string, stdin string, args ...string) error {
			capturedStdin = stdin
			return nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := ApplyNWFilter("abox-test", "abox-test", "abox-test-traffic", "52:54:00:ab:cd:ef", 2)
	if err != nil {
		t.Errorf("ApplyNWFilter() error = %v", err)
	}

	// Verify the generated XML contains expected values
	if !strings.Contains(capturedStdin, "52:54:00:ab:cd:ef") {
		t.Error("ApplyNWFilter() XML should contain MAC address")
	}
	if !strings.Contains(capturedStdin, "filterref filter='abox-test-traffic'") {
		t.Error("ApplyNWFilter() XML should contain filter reference")
	}
	if !strings.Contains(capturedStdin, "<driver name='vhost' queues='2'/>") {
		t.Error("ApplyNWFilter() XML should contain driver element with queues matching cpus")
	}
}

func TestApplyNWFilter_InvalidMAC(t *testing.T) {
	mock := &MockCommander{}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := ApplyNWFilter("abox-test", "abox-test", "abox-test-traffic", "invalid-mac", 2)
	if err == nil {
		t.Error("ApplyNWFilter() expected error for invalid MAC")
	}
	if !strings.Contains(err.Error(), "invalid MAC address") {
		t.Errorf("ApplyNWFilter() error = %v, want containing 'invalid MAC address'", err)
	}
}

func TestRemoveNWFilter_WithMock(t *testing.T) {
	var capturedStdin string
	mock := &MockCommander{
		RunWithStdinFunc: func(name string, stdin string, args ...string) error {
			capturedStdin = stdin
			return nil
		},
	}
	prev := SetCommander(mock)
	defer SetCommander(prev)

	err := RemoveNWFilter("abox-test", "abox-test", "52:54:00:ab:cd:ef", 4)
	if err != nil {
		t.Errorf("RemoveNWFilter() error = %v", err)
	}

	// Verify the generated XML does NOT contain filterref
	if strings.Contains(capturedStdin, "filterref") {
		t.Error("RemoveNWFilter() XML should not contain filterref")
	}
	if !strings.Contains(capturedStdin, "52:54:00:ab:cd:ef") {
		t.Error("RemoveNWFilter() XML should contain MAC address")
	}
	if !strings.Contains(capturedStdin, "<driver name='vhost' queues='4'/>") {
		t.Error("RemoveNWFilter() XML should contain driver element with queues capped at 4")
	}
}

func TestCommandError(t *testing.T) {
	err := &CommandError{
		Command: "virsh list",
		Stderr:  "connection refused",
		Err:     errors.New("exit status 1"),
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "virsh list") {
		t.Errorf("CommandError.Error() should contain command, got %q", errStr)
	}
	if !strings.Contains(errStr, "connection refused") {
		t.Errorf("CommandError.Error() should contain stderr, got %q", errStr)
	}

	// Test Unwrap
	if !errors.Is(err, err.Err) {
		t.Error("CommandError should be unwrappable")
	}
}

func TestGetDomainUUID_WithMock(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		err      error
		expected string
	}{
		{
			name: "valid-xml",
			output: `<domain type='kvm'>
  <name>abox-test</name>
  <uuid>12345678-1234-1234-1234-123456789abc</uuid>
  <memory unit='KiB'>4194304</memory>
</domain>`,
			expected: "12345678-1234-1234-1234-123456789abc",
		},
		{
			name: "uuid-with-whitespace",
			output: `<domain type='kvm'>
  <name>test</name>
  <uuid>  abcd-1234  </uuid>
</domain>`,
			expected: "abcd-1234", // TrimSpace removes outer whitespace
		},
		{
			name:     "virsh-error",
			err:      errors.New("domain not found"),
			expected: "",
		},
		{
			name:     "malformed-xml",
			output:   "<domain><uuid>broken",
			expected: "",
		},
		{
			name:     "no-uuid-element",
			output:   "<domain type='kvm'><name>test</name></domain>",
			expected: "",
		},
		{
			name:     "empty-uuid",
			output:   "<domain><uuid></uuid></domain>",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockCommander{
				RunFunc: func(name string, args ...string) (string, error) {
					return tt.output, tt.err
				},
			}
			prev := SetCommander(mock)
			defer SetCommander(prev)

			result := GetDomainUUID("test-domain")
			if result != tt.expected {
				t.Errorf("GetDomainUUID() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetNWFilterUUID_WithMock(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		err      error
		expected string
	}{
		{
			name: "valid-xml",
			output: `<filter name='abox-test-traffic' chain='root' priority='-500'>
  <uuid>12345678-1234-1234-1234-123456789abc</uuid>
  <rule action='accept' direction='in' priority='100'>
    <all/>
  </rule>
</filter>`,
			expected: "12345678-1234-1234-1234-123456789abc",
		},
		{
			name: "uuid-with-whitespace",
			output: `<filter name='test'>
  <uuid>  abcd-1234  </uuid>
</filter>`,
			expected: "  abcd-1234  ", // xml.Unmarshal preserves inner whitespace
		},
		{
			name:     "virsh-error",
			err:      errors.New("filter not found"),
			expected: "",
		},
		{
			name:     "malformed-xml",
			output:   "<filter><uuid>broken",
			expected: "",
		},
		{
			name:     "no-uuid-element",
			output:   "<filter name='test'><rule/></filter>",
			expected: "",
		},
		{
			name:     "empty-uuid",
			output:   "<filter><uuid></uuid></filter>",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockCommander{
				RunFunc: func(name string, args ...string) (string, error) {
					return tt.output, tt.err
				},
			}
			prev := SetCommander(mock)
			defer SetCommander(prev)

			result := GetNWFilterUUID("test-filter")
			if result != tt.expected {
				t.Errorf("GetNWFilterUUID() = %q, want %q", result, tt.expected)
			}
		})
	}
}
