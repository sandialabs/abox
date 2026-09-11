package firewall

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/rpc"
)

// fakeEgressClient records the requests it receives and returns canned results.
type fakeEgressClient struct {
	rpc.EgressClient // embed so unimplemented methods (Ping/Shutdown) are present

	applyReq  *rpc.EgressReq
	removeReq *rpc.EgressReq
	verifyReq *rpc.EgressReq

	applyErr  error
	removeErr error
	verifyOK  bool
	verifyErr error
}

func (f *fakeEgressClient) Apply(_ context.Context, in *rpc.EgressReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
	f.applyReq = in
	return &rpc.Empty{}, f.applyErr
}

func (f *fakeEgressClient) Remove(_ context.Context, in *rpc.EgressReq, _ ...grpc.CallOption) (*rpc.Empty, error) {
	f.removeReq = in
	return &rpc.Empty{}, f.removeErr
}

func (f *fakeEgressClient) Verify(_ context.Context, in *rpc.EgressReq, _ ...grpc.CallOption) (*rpc.BoolMsg, error) {
	f.verifyReq = in
	return &rpc.BoolMsg{Ok: f.verifyOK}, f.verifyErr
}

// testPolicy is a representative policy used across the enforcer tests.
func testPolicy() backend.EgressPolicy {
	return backend.EgressPolicy{
		DNSPort:      34711,
		HTTPPort:     45123,
		GuestDNSPort: 53,
	}
}

func TestEgressEnforcerApply(t *testing.T) {
	fake := &fakeEgressClient{}
	enf := NewEgressEnforcer(fake)

	if err := enf.Apply(context.Background(), "abox-dev", testPolicy()); err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if fake.applyReq == nil {
		t.Fatal("Apply did not call the client")
	}
	got := fake.applyReq
	if got.Bridge != "abox-dev" || got.DnsPort != 34711 || got.HttpPort != 45123 ||
		got.GuestDnsPort != 53 {
		t.Errorf("unexpected Apply request: %+v", got)
	}
}

func TestEgressEnforcerApplyError(t *testing.T) {
	fake := &fakeEgressClient{applyErr: errors.New("boom")}
	enf := NewEgressEnforcer(fake)

	if err := enf.Apply(context.Background(), "abox-dev", testPolicy()); err == nil {
		t.Fatal("expected error from Apply")
	}
}

func TestEgressEnforcerRemove(t *testing.T) {
	fake := &fakeEgressClient{}
	enf := NewEgressEnforcer(fake)

	if err := enf.Remove(context.Background(), "abox-dev", testPolicy()); err != nil {
		t.Fatalf("Remove returned error: %v", err)
	}
	// Remove carries the ports so the helper can scope its flush.
	if fake.removeReq == nil || fake.removeReq.Bridge != "abox-dev" ||
		fake.removeReq.DnsPort != 34711 || fake.removeReq.HttpPort != 45123 {
		t.Errorf("unexpected Remove request: %+v", fake.removeReq)
	}
}

func TestEgressEnforcerVerify(t *testing.T) {
	fake := &fakeEgressClient{verifyOK: true}
	enf := NewEgressEnforcer(fake)

	ok, err := enf.Verify(context.Background(), "abox-dev", testPolicy())
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to report in-force")
	}
	if fake.verifyReq == nil || fake.verifyReq.Bridge != "abox-dev" {
		t.Errorf("unexpected Verify request: %+v", fake.verifyReq)
	}
}
