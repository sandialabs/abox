package firewall

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/rpc"
)

// mockIPTablesPrivilegeClient implements rpc.PrivilegeClient for iptables testing.
type mockIPTablesPrivilegeClient struct {
	rpc.PrivilegeClient
	iptablesAddFunc    func(ctx context.Context, in *rpc.IptablesReq, opts ...grpc.CallOption) (*rpc.Empty, error)
	iptablesFlushFunc  func(ctx context.Context, in *rpc.IptablesFlushReq, opts ...grpc.CallOption) (*rpc.Empty, error)
	iptablesRemoveFunc func(ctx context.Context, in *rpc.IptablesReq, opts ...grpc.CallOption) (*rpc.Empty, error)
}

func (m *mockIPTablesPrivilegeClient) IptablesAdd(ctx context.Context, in *rpc.IptablesReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.iptablesAddFunc != nil {
		return m.iptablesAddFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

func (m *mockIPTablesPrivilegeClient) IptablesFlush(ctx context.Context, in *rpc.IptablesFlushReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.iptablesFlushFunc != nil {
		return m.iptablesFlushFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

func (m *mockIPTablesPrivilegeClient) IptablesRemove(ctx context.Context, in *rpc.IptablesReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.iptablesRemoveFunc != nil {
		return m.iptablesRemoveFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

func TestIPTablesClient_AddDNSRedirect_Success(t *testing.T) {
	var addCalls int
	mock := &mockIPTablesPrivilegeClient{
		iptablesAddFunc: func(ctx context.Context, in *rpc.IptablesReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			addCalls++
			return &rpc.Empty{}, nil
		},
	}

	inst := &config.Instance{
		Bridge: "abox-dev",
		DNS:    config.DNSConfig{Port: 34711},
	}

	client := NewIPTablesClient(mock)
	err := client.AddDNSRedirect(inst)
	if err != nil {
		t.Fatalf("AddDNSRedirect() error = %v", err)
	}
	// Should add both UDP and TCP rules
	if addCalls != 2 {
		t.Errorf("expected 2 IptablesAdd calls, got %d", addCalls)
	}
}

func TestIPTablesClient_AddDNSRedirect_TCPFailRollsBackUDP(t *testing.T) {
	var addCalls int
	var removeCalls int
	mock := &mockIPTablesPrivilegeClient{
		iptablesAddFunc: func(ctx context.Context, in *rpc.IptablesReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			addCalls++
			// First call (UDP) succeeds, second call (TCP) fails
			if in.Protocol == "tcp" {
				return nil, fmt.Errorf("iptables failed")
			}
			return &rpc.Empty{}, nil
		},
		iptablesRemoveFunc: func(ctx context.Context, in *rpc.IptablesReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			removeCalls++
			return &rpc.Empty{}, nil
		},
	}

	inst := &config.Instance{
		Bridge: "abox-dev",
		DNS:    config.DNSConfig{Port: 34711},
	}

	client := NewIPTablesClient(mock)
	err := client.AddDNSRedirect(inst)
	if err == nil {
		t.Fatal("expected error when TCP rule fails")
	}
	// Should have attempted rollback of UDP rule
	if removeCalls != 1 {
		t.Errorf("expected 1 rollback call, got %d", removeCalls)
	}
}

func TestIPTablesClient_Flush(t *testing.T) {
	var flushed bool
	mock := &mockIPTablesPrivilegeClient{
		iptablesFlushFunc: func(ctx context.Context, in *rpc.IptablesFlushReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			flushed = true
			if in.Bridge != "abox-dev" {
				t.Errorf("Bridge = %q, want %q", in.Bridge, "abox-dev")
			}
			return &rpc.Empty{}, nil
		},
	}

	client := NewIPTablesClient(mock)
	client.Flush("abox-dev")
	if !flushed {
		t.Error("Flush should have called IptablesFlush")
	}
}

func TestIPTablesClient_Flush_ErrorHandled(t *testing.T) {
	mock := &mockIPTablesPrivilegeClient{
		iptablesFlushFunc: func(ctx context.Context, in *rpc.IptablesFlushReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
			return nil, fmt.Errorf("iptables error")
		},
	}

	client := NewIPTablesClient(mock)
	// Flush should not panic on error (it logs but doesn't return error)
	client.Flush("abox-dev")
}
