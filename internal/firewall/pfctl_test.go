//go:build darwin

package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
)

// mockPfctlPrivilegeClient implements rpc.PrivilegeClient for pfctl testing.
type mockPfctlPrivilegeClient struct {
	rpc.PrivilegeClient
	pfctlEnableFunc      func(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.Empty, error)
	pfctlLoadAnchorFunc  func(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error)
	pfctlFlushAnchorFunc func(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error)
}

func (m *mockPfctlPrivilegeClient) PfctlEnable(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.pfctlEnableFunc != nil {
		return m.pfctlEnableFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

func (m *mockPfctlPrivilegeClient) PfctlLoadAnchor(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.pfctlLoadAnchorFunc != nil {
		return m.pfctlLoadAnchorFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

func (m *mockPfctlPrivilegeClient) PfctlFlushAnchor(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.pfctlFlushAnchorFunc != nil {
		return m.pfctlFlushAnchorFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

// withTempHome redirects HOME to a temp directory so marker writes don't
// pollute the real ~/Library/Caches/abox during tests.
func withTempHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestPfctlClient_ApplyInstanceRules_Success(t *testing.T) {
	withTempHome(t)
	var loadedReq *rpc.PfctlAnchorReq
	mock := &mockPfctlPrivilegeClient{
		pfctlLoadAnchorFunc: func(_ context.Context, in *rpc.PfctlAnchorReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
			loadedReq = in
			return &rpc.Empty{}, nil
		},
	}

	client := NewPfctlClient(mock)
	if err := client.ApplyInstanceRules("dev", "192.168.64.5", "192.168.64.1", 5353, 8443); err != nil {
		t.Fatalf("ApplyInstanceRules() error = %v", err)
	}

	if loadedReq == nil {
		t.Fatal("PfctlLoadAnchor was not called")
	}
	if loadedReq.InstanceName != "dev" {
		t.Errorf("InstanceName = %q, want %q", loadedReq.InstanceName, "dev")
	}

	content := loadedReq.RulesContent
	for _, want := range []string{
		"rdr pass proto udp from 192.168.64.5 to any port 53 -> 127.0.0.1 port 5353",
		"rdr pass proto tcp from 192.168.64.5 to any port 53 -> 127.0.0.1 port 5353",
		"pass quick proto udp from 192.168.64.5 port 68 to any port 67",
		"pass quick proto tcp from 192.168.64.5 to 192.168.64.1 port 8443",
		"pass quick proto icmp from 192.168.64.5 to 192.168.64.1",
		"block drop quick from 192.168.64.5 to any",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("missing rule %q in:\n%s", want, content)
		}
	}

	if !FilterMarkerExists("abox-dev-traffic") {
		t.Error("filter marker should exist after ApplyInstanceRules")
	}
}

func TestPfctlClient_ApplyInstanceRules_RPCError(t *testing.T) {
	withTempHome(t)
	mock := &mockPfctlPrivilegeClient{
		pfctlLoadAnchorFunc: func(_ context.Context, _ *rpc.PfctlAnchorReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
			return nil, fmt.Errorf("pfctl failed")
		},
	}

	client := NewPfctlClient(mock)
	if err := client.ApplyInstanceRules("dev", "192.168.64.5", "192.168.64.1", 5353, 8443); err == nil {
		t.Fatal("expected error when RPC fails")
	}

	if FilterMarkerExists("abox-dev-traffic") {
		t.Error("filter marker must not be written when RPC fails")
	}
}

func TestPfctlClient_EnsureEnabled_Success(t *testing.T) {
	var called bool
	mock := &mockPfctlPrivilegeClient{
		pfctlEnableFunc: func(_ context.Context, _ *rpc.Empty, _ ...grpc.CallOption) (*rpc.Empty, error) {
			called = true
			return &rpc.Empty{}, nil
		},
	}

	client := NewPfctlClient(mock)
	if err := client.EnsureEnabled(); err != nil {
		t.Fatalf("EnsureEnabled() error = %v", err)
	}
	if !called {
		t.Error("PfctlEnable was not called")
	}
}

func TestPfctlClient_Flush(t *testing.T) {
	withTempHome(t)
	// Seed a marker so we can verify it is cleaned up.
	if err := writeFilterMarker("abox-dev-traffic"); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	var flushedName string
	mock := &mockPfctlPrivilegeClient{
		pfctlFlushAnchorFunc: func(_ context.Context, in *rpc.PfctlAnchorReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
			flushedName = in.InstanceName
			return &rpc.Empty{}, nil
		},
	}

	client := NewPfctlClient(mock)
	client.Flush("dev")
	if flushedName != "dev" {
		t.Errorf("Flush instance = %q, want %q", flushedName, "dev")
	}
	if FilterMarkerExists("abox-dev-traffic") {
		t.Error("filter marker should be removed after Flush")
	}
}

func TestPfctlClient_Flush_ErrorHandled(t *testing.T) {
	withTempHome(t)
	mock := &mockPfctlPrivilegeClient{
		pfctlFlushAnchorFunc: func(_ context.Context, _ *rpc.PfctlAnchorReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
			return nil, fmt.Errorf("pfctl error")
		},
	}

	client := NewPfctlClient(mock)
	// Flush is best-effort; must not panic on RPC error.
	client.Flush("dev")
}

func TestBuildInstanceRules(t *testing.T) {
	rules := buildInstanceRules("192.168.64.5", "192.168.64.1", 5353, 8443)

	// Order matters: rdr rules must precede filter rules in a PF ruleset.
	rdrIdx := strings.Index(rules, "rdr pass proto udp")
	passIdx := strings.Index(rules, "pass quick proto udp from 192.168.64.5 port 68")
	blockIdx := strings.Index(rules, "block drop quick from 192.168.64.5 to any")

	if rdrIdx < 0 || passIdx < 0 || blockIdx < 0 {
		t.Fatalf("missing expected rule category in:\n%s", rules)
	}
	if rdrIdx >= passIdx || passIdx >= blockIdx {
		t.Errorf("rules out of order (rdr=%d pass=%d block=%d):\n%s",
			rdrIdx, passIdx, blockIdx, rules)
	}
}

func TestValidatePfctlArgs(t *testing.T) {
	tests := []struct {
		name     string
		inst     string
		vmIP     string
		gateway  string
		dnsPort  int
		httpPort int
		wantErr  bool
	}{
		{name: "valid", inst: "dev", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 8443},
		{name: "empty name", inst: "", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 8443, wantErr: true},
		{name: "unsafe name", inst: "dev;rm", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 8443, wantErr: true},
		{name: "invalid vmIP", inst: "dev", vmIP: "not-ip", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 8443, wantErr: true},
		{name: "empty vmIP", inst: "dev", vmIP: "", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 8443, wantErr: true},
		{name: "IPv6 vmIP", inst: "dev", vmIP: "::1", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 8443, wantErr: true},
		{name: "invalid gateway", inst: "dev", vmIP: "192.168.64.5", gateway: "bad", dnsPort: 5353, httpPort: 8443, wantErr: true},
		{name: "dns port too low", inst: "dev", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 53, httpPort: 8443, wantErr: true},
		{name: "dns port too high", inst: "dev", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 70000, httpPort: 8443, wantErr: true},
		{name: "http port too low", inst: "dev", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 80, wantErr: true},
		{name: "http port too high", inst: "dev", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 70000, wantErr: true},
		{name: "dns port lower bound", inst: "dev", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 1024, httpPort: 8443},
		{name: "http port upper bound", inst: "dev", vmIP: "192.168.64.5", gateway: "192.168.64.1", dnsPort: 5353, httpPort: 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePfctlArgs(tt.inst, tt.vmIP, tt.gateway, tt.dnsPort, tt.httpPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePfctlArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFilterMarkerLifecycle(t *testing.T) {
	withTempHome(t)

	if FilterMarkerExists("abox-dev-traffic") {
		t.Fatal("marker unexpectedly present at start")
	}

	if err := writeFilterMarker("abox-dev-traffic"); err != nil {
		t.Fatalf("writeFilterMarker: %v", err)
	}
	if !FilterMarkerExists("abox-dev-traffic") {
		t.Error("marker missing after write")
	}

	// Sanity: marker lives under ~/Library/Caches/abox/filters/.
	path, _ := filterMarkerPath("abox-dev-traffic")
	if !strings.Contains(filepath.ToSlash(path), "Library/Caches/abox/filters/abox-dev-traffic.applied") {
		t.Errorf("unexpected marker path: %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("stat marker: %v", err)
	}

	if err := removeFilterMarker("abox-dev-traffic"); err != nil {
		t.Errorf("removeFilterMarker: %v", err)
	}
	if FilterMarkerExists("abox-dev-traffic") {
		t.Error("marker still present after remove")
	}

	// Remove on missing marker should be a no-op, not an error.
	if err := removeFilterMarker("abox-dev-traffic"); err != nil {
		t.Errorf("removeFilterMarker on missing marker: %v", err)
	}
}
