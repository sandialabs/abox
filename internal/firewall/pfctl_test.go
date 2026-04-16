//go:build darwin

package firewall

import (
	"context"
	"fmt"
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

func TestPfctlClient_AddDNSRedirect_Success(t *testing.T) {
	var loadedReq *rpc.PfctlAnchorReq
	mock := &mockPfctlPrivilegeClient{
		pfctlLoadAnchorFunc: func(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			loadedReq = in
			return &rpc.Empty{}, nil
		},
	}

	client := NewPfctlClient(mock)
	err := client.AddDNSRedirect("dev", "192.168.64.5", 5353)
	if err != nil {
		t.Fatalf("AddDNSRedirect() error = %v", err)
	}

	if loadedReq == nil {
		t.Fatal("PfctlLoadAnchor was not called")
	}
	if loadedReq.InstanceName != "dev" {
		t.Errorf("InstanceName = %q, want %q", loadedReq.InstanceName, "dev")
	}
	if !strings.Contains(loadedReq.RulesContent, "192.168.64.5") {
		t.Errorf("rules should contain VM IP, got:\n%s", loadedReq.RulesContent)
	}
	if !strings.Contains(loadedReq.RulesContent, "port 5353") {
		t.Errorf("rules should contain DNS port, got:\n%s", loadedReq.RulesContent)
	}
}

func TestPfctlClient_AddDNSRedirect_RPCError(t *testing.T) {
	mock := &mockPfctlPrivilegeClient{
		pfctlLoadAnchorFunc: func(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			return nil, fmt.Errorf("pfctl failed")
		},
	}

	client := NewPfctlClient(mock)
	err := client.AddDNSRedirect("dev", "192.168.64.5", 5353)
	if err == nil {
		t.Fatal("expected error when RPC fails")
	}
}

func TestPfctlClient_EnsureEnabled_Success(t *testing.T) {
	var called bool
	mock := &mockPfctlPrivilegeClient{
		pfctlEnableFunc: func(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.Empty, error) {
			called = true
			return &rpc.Empty{}, nil
		},
	}

	client := NewPfctlClient(mock)
	err := client.EnsureEnabled()
	if err != nil {
		t.Fatalf("EnsureEnabled() error = %v", err)
	}
	if !called {
		t.Error("PfctlEnable was not called")
	}
}

func TestPfctlClient_Flush(t *testing.T) {
	var flushedName string
	mock := &mockPfctlPrivilegeClient{
		pfctlFlushAnchorFunc: func(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			flushedName = in.InstanceName
			return &rpc.Empty{}, nil
		},
	}

	client := NewPfctlClient(mock)
	client.Flush("dev")
	if flushedName != "dev" {
		t.Errorf("Flush instance = %q, want %q", flushedName, "dev")
	}
}

func TestPfctlClient_Flush_ErrorHandled(t *testing.T) {
	mock := &mockPfctlPrivilegeClient{
		pfctlFlushAnchorFunc: func(ctx context.Context, in *rpc.PfctlAnchorReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			return nil, fmt.Errorf("pfctl error")
		},
	}

	client := NewPfctlClient(mock)
	// Flush should not panic on error (it logs but doesn't return error)
	client.Flush("dev")
}

func TestBuildDNSRedirectRules(t *testing.T) {
	rules := buildDNSRedirectRules("192.168.64.5", 5353)

	if !strings.Contains(rules, "rdr pass proto udp from 192.168.64.5 to any port 53 -> 127.0.0.1 port 5353") {
		t.Errorf("missing UDP redirect rule in:\n%s", rules)
	}
	if !strings.Contains(rules, "rdr pass proto tcp from 192.168.64.5 to any port 53 -> 127.0.0.1 port 5353") {
		t.Errorf("missing TCP redirect rule in:\n%s", rules)
	}
}

func TestValidatePfctlArgs(t *testing.T) {
	tests := []struct {
		name    string
		inst    string
		vmIP    string
		dnsPort int
		wantErr bool
	}{
		{name: "valid", inst: "dev", vmIP: "192.168.64.5", dnsPort: 5353},
		{name: "empty name", inst: "", vmIP: "192.168.64.5", dnsPort: 5353, wantErr: true},
		{name: "unsafe name", inst: "dev;rm", vmIP: "192.168.64.5", dnsPort: 5353, wantErr: true},
		{name: "invalid IP", inst: "dev", vmIP: "not-ip", dnsPort: 5353, wantErr: true},
		{name: "empty IP", inst: "dev", vmIP: "", dnsPort: 5353, wantErr: true},
		{name: "IPv6", inst: "dev", vmIP: "::1", dnsPort: 5353, wantErr: true},
		{name: "port too low", inst: "dev", vmIP: "192.168.64.5", dnsPort: 53, wantErr: true},
		{name: "port too high", inst: "dev", vmIP: "192.168.64.5", dnsPort: 70000, wantErr: true},
		{name: "port lower bound", inst: "dev", vmIP: "192.168.64.5", dnsPort: 1024},
		{name: "port upper bound", inst: "dev", vmIP: "192.168.64.5", dnsPort: 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePfctlArgs(tt.inst, tt.vmIP, tt.dnsPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePfctlArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
