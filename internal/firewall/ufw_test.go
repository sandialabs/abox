package firewall

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/rpc"
)

// mockUFWPrivilegeClient implements rpc.PrivilegeClient for UFW testing.
type mockUFWPrivilegeClient struct {
	rpc.PrivilegeClient
	ufwStatusFunc func(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.UfwStatusResp, error)
	ufwAddFunc    func(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error)
	ufwRemoveFunc func(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error)
}

func (m *mockUFWPrivilegeClient) UfwStatus(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.UfwStatusResp, error) {
	if m.ufwStatusFunc != nil {
		return m.ufwStatusFunc(ctx, in, opts...)
	}
	return &rpc.UfwStatusResp{}, nil
}

func (m *mockUFWPrivilegeClient) UfwAdd(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.ufwAddFunc != nil {
		return m.ufwAddFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

func (m *mockUFWPrivilegeClient) UfwRemove(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
	if m.ufwRemoveFunc != nil {
		return m.ufwRemoveFunc(ctx, in, opts...)
	}
	return &rpc.Empty{}, nil
}

func TestUFWClient_IsActive(t *testing.T) {
	tests := []struct {
		name string
		resp *rpc.UfwStatusResp
		err  error
		want bool
	}{
		{
			"installed and active",
			&rpc.UfwStatusResp{Installed: true, Active: true},
			nil,
			true,
		},
		{
			"installed but inactive",
			&rpc.UfwStatusResp{Installed: true, Active: false},
			nil,
			false,
		},
		{
			"not installed",
			&rpc.UfwStatusResp{Installed: false, Active: false},
			nil,
			false,
		},
		{
			"RPC error",
			nil,
			fmt.Errorf("connection refused"),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockUFWPrivilegeClient{
				ufwStatusFunc: func(ctx context.Context, in *rpc.Empty, opts ...grpc.CallOption) (*rpc.UfwStatusResp, error) {
					return tt.resp, tt.err
				},
			}
			client := NewUFWClient(mock)
			got := client.IsActive()
			if got != tt.want {
				t.Errorf("IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUFWClient_Allow(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockUFWPrivilegeClient{
			ufwAddFunc: func(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
				if in.Bridge != "abox-dev" {
					t.Errorf("Bridge = %q, want %q", in.Bridge, "abox-dev")
				}
				return &rpc.Empty{}, nil
			},
		}
		client := NewUFWClient(mock)
		if err := client.Allow("abox-dev"); err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
	})

	t.Run("error", func(t *testing.T) {
		mock := &mockUFWPrivilegeClient{
			ufwAddFunc: func(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
				return nil, fmt.Errorf("ufw failed")
			},
		}
		client := NewUFWClient(mock)
		if err := client.Allow("abox-dev"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestUFWClient_Remove(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockUFWPrivilegeClient{
			ufwRemoveFunc: func(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
				return &rpc.Empty{}, nil
			},
		}
		client := NewUFWClient(mock)
		if err := client.Remove("abox-dev"); err != nil {
			t.Fatalf("Remove() error = %v", err)
		}
	})

	t.Run("error", func(t *testing.T) {
		mock := &mockUFWPrivilegeClient{
			ufwRemoveFunc: func(ctx context.Context, in *rpc.UfwReq, opts ...grpc.CallOption) (*rpc.Empty, error) {
				return nil, fmt.Errorf("ufw failed")
			},
		}
		client := NewUFWClient(mock)
		if err := client.Remove("abox-dev"); err == nil {
			t.Fatal("expected error")
		}
	})
}
