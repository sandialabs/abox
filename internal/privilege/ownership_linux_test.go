//go:build linux

package privilege

import (
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/rpc"
)

// TestBridgeDerivationsMatchConfig pins the helper's hardcoded (TCB) bridge
// derivations to the config package's: the helper authorizes by recomputing
// what config generates, so any drift between the two silently locks every
// caller out of (or worse, mis-scopes) their own bridges. Tests may import
// config; the production helper code must not.
func TestBridgeDerivationsMatchConfig(t *testing.T) {
	cases := []struct {
		uid  int
		name string
	}{
		{0, "dev"},
		{1000, "dev"},
		{2000, "dev"},
		{1000, "my-instance"},
		{1000, "a12345678901234567890123456789012345678901234567890123456789012"},
	}
	for _, c := range cases {
		if got, want := ownedBridgeName(c.uid, c.name), config.GenerateBridgeName(c.uid, c.name); got != want {
			t.Errorf("ownedBridgeName(%d, %q) = %q, config.GenerateBridgeName = %q", c.uid, c.name, got, want)
		}
	}
	for _, name := range []string{"dev", "myinstance", "verylonginstancename"} {
		if got, want := legacyBridgeName(name), config.LegacyBridgeName(name); got != want {
			t.Errorf("legacyBridgeName(%q) = %q, config.LegacyBridgeName = %q", name, got, want)
		}
	}
}

// TestBridgeNamespacesDisjoint pins the security property that no legacy
// derivation can ever name a per-user bridge: legacy-leniency teardown
// authorization must not be reachable for another user's current bridge via an
// offline search for a colliding legacy name.
func TestBridgeNamespacesDisjoint(t *testing.T) {
	if got := ownedBridgeName(1000, "dev"); !strings.HasPrefix(got, "abx-") || len(got) != 15 {
		t.Errorf("ownedBridgeName = %q, want \"abx-\" prefix and 15 chars", got)
	}
	for _, name := range []string{"dev", "verylonginstancename"} {
		if legacy := legacyBridgeName(name); strings.HasPrefix(legacy, "abx-") {
			t.Errorf("legacyBridgeName(%q) = %q collides with the per-user namespace", name, legacy)
		}
	}
}

func TestAuthorizeBridge(t *testing.T) {
	const uid = 1000
	owned := ownedBridgeName(uid, "dev")

	tests := []struct {
		name    string
		req     *rpc.EgressReq
		op      egressOp
		wantErr string // substring; "" = authorized
	}{
		{"owned bridge apply", &rpc.EgressReq{Bridge: owned, Instance: "dev"}, egressApply, ""},
		{"owned bridge remove", &rpc.EgressReq{Bridge: owned, Instance: "dev"}, egressRemove, ""},
		{"owned bridge verify", &rpc.EgressReq{Bridge: owned, Instance: "dev"}, egressVerify, ""},
		{"another uid's bridge", &rpc.EgressReq{Bridge: ownedBridgeName(2000, "dev"), Instance: "dev"}, egressApply, "not derivable"},
		{"another uid's bridge remove", &rpc.EgressReq{Bridge: ownedBridgeName(2000, "dev"), Instance: "dev"}, egressRemove, "not derivable"},
		{"bridge for a different instance", &rpc.EgressReq{Bridge: ownedBridgeName(uid, "other"), Instance: "dev"}, egressApply, "not derivable"},
		{"legacy bridge apply refused", &rpc.EgressReq{Bridge: "abox-dev", Instance: "dev"}, egressApply, "legacy shared-name scheme"},
		{"legacy bridge remove allowed", &rpc.EgressReq{Bridge: "abox-dev", Instance: "dev"}, egressRemove, ""},
		{"legacy bridge verify allowed", &rpc.EgressReq{Bridge: "abox-dev", Instance: "dev"}, egressVerify, ""},
		{"legacy hashed bridge remove allowed", &rpc.EgressReq{Bridge: legacyBridgeName("verylonginstancename"), Instance: "verylonginstancename"}, egressRemove, ""},
		{"legacy bridge wrong instance", &rpc.EgressReq{Bridge: "abox-dev", Instance: "other"}, egressRemove, "not derivable"},
		{"vmnet apply allowed", &rpc.EgressReq{Bridge: "vmnet7", Instance: "dev"}, egressApply, ""},
		{"vmnet remove allowed", &rpc.EgressReq{Bridge: "vmnet7", Instance: "dev"}, egressRemove, ""},
		{"empty instance refused", &rpc.EgressReq{Bridge: owned}, egressApply, "no instance name"},
		{"empty instance refused on remove", &rpc.EgressReq{Bridge: owned}, egressRemove, "no instance name"},
		{"malformed instance refused", &rpc.EgressReq{Bridge: owned, Instance: "../etc"}, egressApply, "invalid instance name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizeBridge(uid, tt.req, tt.op)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("authorizeBridge = %v, want authorized", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("authorizeBridge = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("authorizeBridge error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
