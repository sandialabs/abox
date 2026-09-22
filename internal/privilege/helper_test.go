package privilege

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/sandialabs/abox/internal/rpc"
)

func TestTokenAuthInterceptor(t *testing.T) {
	interceptor := tokenAuthInterceptor("test-token-must-be-at-least-32-chars")
	noopHandler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	t.Run("ping bypasses auth", func(t *testing.T) {
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Ping_FullMethodName}
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
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Apply_FullMethodName}
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
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Apply_FullMethodName}
		_, err := interceptor(ctx, nil, info, noopHandler)
		if err == nil {
			t.Fatal("expected error for invalid token")
		}
	})

	t.Run("missing metadata rejected", func(t *testing.T) {
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Apply_FullMethodName}
		_, err := interceptor(context.Background(), nil, info, noopHandler)
		if err == nil {
			t.Fatal("expected error for missing metadata")
		}
	})

	t.Run("missing authorization rejected", func(t *testing.T) {
		md := metadata.Pairs("other-key", "value")
		ctx := metadata.NewIncomingContext(context.Background(), md)
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Apply_FullMethodName}
		_, err := interceptor(ctx, nil, info, noopHandler)
		if err == nil {
			t.Fatal("expected error for missing authorization")
		}
	})
}

func TestAuditInterceptor(t *testing.T) {
	interceptor := auditInterceptor(1000)

	t.Run("ping skipped", func(t *testing.T) {
		handler := func(ctx context.Context, req any) (any, error) {
			return "pong", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Ping_FullMethodName}
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
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Apply_FullMethodName}
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
		info := &grpc.UnaryServerInfo{FullMethod: rpc.Egress_Apply_FullMethodName}
		_, err := interceptor(context.Background(), nil, info, handler)
		if err == nil {
			t.Fatal("expected error to be propagated")
		}
	})
}
