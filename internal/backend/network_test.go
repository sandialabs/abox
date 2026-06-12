package backend

import "testing"

// subnetMockBackend embeds mockBackend and implements SubnetProvider, modeling a
// backend (e.g. vfkit on macOS) that manages its own subnet pool.
type subnetMockBackend struct {
	mockBackend
	gateway string
	subnet  string
}

func (s *subnetMockBackend) NetworkDefaults() (gateway, subnet string) {
	return s.gateway, s.subnet
}

func TestDeriveIPAddress(t *testing.T) {
	tests := []struct {
		gateway string
		want    string
	}{
		{"10.10.20.1", "10.10.20.10"},
		{"192.168.128.1", "192.168.128.10"},
		{"192.168.130.1", "192.168.130.10"},
	}
	for _, tt := range tests {
		if got := DeriveIPAddress(tt.gateway); got != tt.want {
			t.Errorf("DeriveIPAddress(%q) = %q, want %q", tt.gateway, got, tt.want)
		}
	}
}

func TestResolveNetwork(t *testing.T) {
	t.Run("SubnetProvider backend uses managed network", func(t *testing.T) {
		be := &subnetMockBackend{gateway: "192.168.130.1", subnet: "192.168.130.0/24"}
		subnet, gateway, ip, err := ResolveNetwork(be, "")
		if err != nil {
			t.Fatalf("ResolveNetwork() = %v", err)
		}
		if subnet != "192.168.130.0/24" {
			t.Errorf("subnet = %q, want 192.168.130.0/24", subnet)
		}
		if gateway != "192.168.130.1" {
			t.Errorf("gateway = %q, want 192.168.130.1", gateway)
		}
		if ip != "192.168.130.10" {
			t.Errorf("ip = %q, want 192.168.130.10", ip)
		}
	})

	t.Run("explicit user subnet is validated and used", func(t *testing.T) {
		// A SubnetProvider backend must still honor an explicit --subnet.
		be := &subnetMockBackend{gateway: "192.168.130.1", subnet: "192.168.130.0/24"}
		subnet, gateway, ip, err := ResolveNetwork(be, "10.10.50.0/24")
		if err != nil {
			t.Fatalf("ResolveNetwork() = %v", err)
		}
		if subnet != "10.10.50.0/24" {
			t.Errorf("subnet = %q, want 10.10.50.0/24", subnet)
		}
		if gateway != "10.10.50.1" {
			t.Errorf("gateway = %q, want 10.10.50.1", gateway)
		}
		if ip != "10.10.50.10" {
			t.Errorf("ip = %q, want 10.10.50.10", ip)
		}
	})

	t.Run("invalid user subnet errors", func(t *testing.T) {
		be := &mockBackend{name: "plain"}
		if _, _, _, err := ResolveNetwork(be, "not-a-subnet"); err == nil {
			t.Error("ResolveNetwork() with invalid subnet = nil error, want error")
		}
	})
}
