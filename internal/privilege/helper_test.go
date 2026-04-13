package privilege

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/sandialabs/abox/internal/rpc"
)

func TestValidateDiskSize_Helper(t *testing.T) {
	tests := []struct {
		name    string
		size    string
		wantErr bool
	}{
		{"valid 20G", "20G", false},
		{"valid 1G", "1G", false},
		{"valid 10T", "10T", false},
		{"valid 10240G", "10240G", false},
		{"invalid suffix M", "100M", true},
		{"zero G", "0G", true},
		{"too large T", "11T", true},
		{"too large G", "10241G", true},
		{"empty string", "", true},
		{"no suffix", "abc", true},
		{"just suffix", "G", true},
		{"negative", "-1G", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiskSize(tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDiskSize(%q) error = %v, wantErr %v", tt.size, err, tt.wantErr)
			}
		})
	}
}

func TestExtractDportFromRule(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{
			"valid rule",
			"-A INPUT -i ab-dev -p udp -m udp --dport 34711 -j ACCEPT",
			34711,
		},
		{
			"missing dport",
			"-A INPUT -i ab-dev -p udp -j ACCEPT",
			0,
		},
		{
			"invalid port value",
			"-A INPUT --dport notanumber -j ACCEPT",
			0,
		},
		{
			"dport as last field",
			"-A INPUT --dport",
			0,
		},
		{
			"port 53",
			"-A PREROUTING -i ab-dev --dport 53 -j REDIRECT",
			53,
		},
		{
			"port 65535",
			"-A INPUT --dport 65535 -j ACCEPT",
			65535,
		},
		{
			"port 0",
			"-A INPUT --dport 0 -j ACCEPT",
			0,
		},
		{
			"empty line",
			"",
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDportFromRule(tt.line)
			if got != tt.want {
				t.Errorf("extractDportFromRule(%q) = %d, want %d", tt.line, got, tt.want)
			}
		})
	}
}

func TestValidateIptablesReq(t *testing.T) {
	tests := []struct {
		name    string
		req     *rpc.IptablesReq
		wantErr bool
	}{
		{
			"valid UDP",
			&rpc.IptablesReq{Bridge: "ab-dev", Protocol: "udp", DnsPort: 34711},
			false,
		},
		{
			"valid TCP",
			&rpc.IptablesReq{Bridge: "abox-test", Protocol: "tcp", DnsPort: 5353},
			false,
		},
		{
			"invalid bridge prefix",
			&rpc.IptablesReq{Bridge: "br-dev", Protocol: "udp", DnsPort: 34711},
			true,
		},
		{
			"invalid protocol",
			&rpc.IptablesReq{Bridge: "ab-dev", Protocol: "icmp", DnsPort: 34711},
			true,
		},
		{
			"port too low",
			&rpc.IptablesReq{Bridge: "ab-dev", Protocol: "udp", DnsPort: 53},
			true,
		},
		{
			"port too high",
			&rpc.IptablesReq{Bridge: "ab-dev", Protocol: "udp", DnsPort: 65536},
			true,
		},
		{
			"port at max",
			&rpc.IptablesReq{Bridge: "ab-dev", Protocol: "tcp", DnsPort: 65535},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateIptablesReq(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIptablesReq() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuthInterceptor(t *testing.T) {
	interceptor := tokenAuthInterceptor("test-token-must-be-at-least-32-chars")
	noopHandler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	t.Run("ping bypasses auth", func(t *testing.T) {
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Privilege_Ping_FullMethodName}
		resp, err := interceptor(context.Background(), nil, info, noopHandler)
		if err != nil {
			t.Fatalf("expected no error for Ping, got %v", err)
		}
		if resp != "ok" {
			t.Errorf("expected 'ok', got %v", resp)
		}
	})

	t.Run("valid token passes", func(t *testing.T) {
		md := metadata.Pairs("authorization", "test-token-must-be-at-least-32-chars")
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: "/abox.Privilege/QemuImgCreate"}
		resp, err := interceptor(ctx, nil, info, noopHandler)
		if err != nil {
			t.Fatalf("expected no error for valid token, got %v", err)
		}
		if resp != "ok" {
			t.Errorf("expected 'ok', got %v", resp)
		}
	})

	t.Run("invalid token rejected", func(t *testing.T) {
		md := metadata.Pairs("authorization", "wrong-token-that-is-long-enough-for-test")
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: "/abox.Privilege/QemuImgCreate"}
		_, err := interceptor(ctx, nil, info, noopHandler)
		if err == nil {
			t.Fatal("expected error for invalid token")
		}
	})

	t.Run("missing metadata rejected", func(t *testing.T) {
		info := &grpc.UnaryServerInfo{FullMethod: "/abox.Privilege/QemuImgCreate"}
		_, err := interceptor(context.Background(), nil, info, noopHandler)
		if err == nil {
			t.Fatal("expected error for missing metadata")
		}
	})

	t.Run("missing authorization rejected", func(t *testing.T) {
		md := metadata.Pairs("other-key", "value")
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: "/abox.Privilege/QemuImgCreate"}
		_, err := interceptor(ctx, nil, info, noopHandler)
		if err == nil {
			t.Fatal("expected error for missing authorization")
		}
	})
}

func TestAuditInterceptor(t *testing.T) {
	interceptor := auditInterceptor()

	t.Run("ping skipped", func(t *testing.T) {
		handler := func(ctx context.Context, req any) (any, error) {
			return "pong", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Privilege_Ping_FullMethodName}
		resp, err := interceptor(context.Background(), nil, info, handler)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != "pong" {
			t.Errorf("expected 'pong', got %v", resp)
		}
	})

	t.Run("success logged", func(t *testing.T) {
		handler := func(ctx context.Context, req any) (any, error) {
			return "result", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/abox.Privilege/QemuImgCreate"}
		resp, err := interceptor(context.Background(), nil, info, handler)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != "result" {
			t.Errorf("expected 'result', got %v", resp)
		}
	})

	t.Run("error logged", func(t *testing.T) {
		handler := func(ctx context.Context, req any) (any, error) {
			return nil, context.DeadlineExceeded
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/abox.Privilege/QemuImgCreate"}
		_, err := interceptor(context.Background(), nil, info, handler)
		if err == nil {
			t.Fatal("expected error to be propagated")
		}
	})
}
