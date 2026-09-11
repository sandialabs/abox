package pfvalidate

import "testing"

func TestParseSubnet24(t *testing.T) {
	t.Run("valid /24 derives .1 gateway", func(t *testing.T) {
		network, gw, err := ParseSubnet24("10.20.30.0/24")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := network.String(); got != "10.20.30.0/24" {
			t.Errorf("network = %q, want 10.20.30.0/24", got)
		}
		if got := gw.String(); got != "10.20.30.1" {
			t.Errorf("gateway = %q, want 10.20.30.1", got)
		}
	})

	rejects := []struct {
		name   string
		subnet string
	}{
		{"empty", ""},
		{"not a /24", "10.20.30.0/16"},
		{"non-network address", "10.20.30.5/24"},
		{"garbage", "not-a-cidr"},
		{"ipv6", "fd00::/24"},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseSubnet24(tc.subnet); err == nil {
				t.Fatalf("expected rejection for %q", tc.subnet)
			}
		})
	}
}

func TestValidateInstanceName(t *testing.T) {
	good := []string{"dev", "my-box", "abc123", "A-B-9", "9lives", "0"}
	for _, n := range good {
		if err := ValidateInstanceName(n); err != nil {
			t.Errorf("expected %q valid: %v", n, err)
		}
	}
	// Leading digit is intentionally ACCEPTED (unlike internal/validation);
	// underscore is REJECTED; leading dash is REJECTED.
	bad := []string{"", "-leading", "has space", "under_score", "slash/x", "dot.name", "semi;colon", "utfé"}
	for _, n := range bad {
		if err := ValidateInstanceName(n); err == nil {
			t.Errorf("expected %q invalid", n)
		}
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{1023, false},
		{1024, true},
		{8080, true},
		{65535, true},
		{65536, false},
		{0, false},
		{-1, false},
	}
	for _, tc := range tests {
		if got := ValidatePort(tc.port); got != tc.want {
			t.Errorf("ValidatePort(%d) = %v, want %v", tc.port, got, tc.want)
		}
	}
}

func TestMatchBridgeName(t *testing.T) {
	accept := []string{"bridge0", "bridge100", "vmnet3", "vmnet19"}
	for _, s := range accept {
		if !MatchBridgeName(s) {
			t.Errorf("expected %q accepted", s)
		}
	}
	reject := []string{"", "bridge", "vmnet", "vmnetX", "en0", "bridge100; rm -rf", "bridge-1"}
	for _, s := range reject {
		if MatchBridgeName(s) {
			t.Errorf("expected %q rejected", s)
		}
	}
}
