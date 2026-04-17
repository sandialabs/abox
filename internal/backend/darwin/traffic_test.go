//go:build darwin

package darwin

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/rpc"
)

// stubPrivilegeClient is the minimal PrivilegeClient implementation needed by
// PfctlClient in these tests: PfctlLoadAnchor and PfctlFlushAnchor. The
// embedded interface gives us a nil base that would panic if any other method
// is called, which is fine — this stub is only wired to PfctlClient.
type stubPrivilegeClient struct {
	rpc.PrivilegeClient
}

func (stubPrivilegeClient) PfctlLoadAnchor(_ context.Context, _ *rpc.PfctlAnchorReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
	return &rpc.Empty{}, nil
}

func (stubPrivilegeClient) PfctlFlushAnchor(_ context.Context, _ *rpc.PfctlAnchorReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
	return &rpc.Empty{}, nil
}

func TestTrafficInterceptor_NoOpMethods(t *testing.T) {
	ti := &TrafficInterceptor{}
	ctx := context.Background()

	if err := ti.DefineFilter(ctx, nil); err != nil {
		t.Errorf("DefineFilter: %v", err)
	}
	if err := ti.ApplyFilter(ctx, "", "", "", "", 0); err != nil {
		t.Errorf("ApplyFilter: %v", err)
	}
	if err := ti.RemoveFilter(ctx, "", "", "", 0); err != nil {
		t.Errorf("RemoveFilter: %v", err)
	}
	if err := ti.DeleteFilter(ctx, ""); err != nil {
		t.Errorf("DeleteFilter: %v", err)
	}
	if got := ti.GetFilterUUID("abox-dev-traffic"); got != "" {
		t.Errorf("GetFilterUUID = %q, want empty string", got)
	}
}

func TestTrafficInterceptor_FilterExists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ti := &TrafficInterceptor{}
	filter := "abox-dev-traffic"

	if ti.FilterExists(filter) {
		t.Fatal("FilterExists should be false before any marker is written")
	}

	// Write a marker via the firewall package (the only supported way the
	// marker gets created in production, via pfctl.ApplyInstanceRules).
	// Exposed internals are not available cross-package, so we verify
	// the public contract: after a successful ApplyInstanceRules call,
	// FilterExists reports true.
	if err := firewall.NewPfctlClient(stubPrivilegeClient{}).ApplyInstanceRules(
		"dev", "192.168.64.5", "192.168.64.1", 5353, 8443,
	); err != nil {
		t.Fatalf("ApplyInstanceRules: %v", err)
	}

	if !ti.FilterExists(filter) {
		t.Error("FilterExists should be true after ApplyInstanceRules")
	}

	// Flush should make FilterExists return false again.
	firewall.NewPfctlClient(stubPrivilegeClient{}).Flush("dev")
	if ti.FilterExists(filter) {
		t.Error("FilterExists should be false after Flush")
	}
}
