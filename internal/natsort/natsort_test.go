package natsort

import "testing"

func TestLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"", "", false},
		{"", "a", true},
		{"a", "", false},
		{"a", "a", false},
		{"a", "b", true},
		{"b", "a", false},
		{"item-2", "item-10", true},
		{"item-10", "item-2", false},
		{"almalinux-8", "almalinux-9", true},
		{"almalinux-9", "almalinux-10", true},
		{"almalinux-10", "almalinux-8", false},
		{"debian-12", "debian-13", true},
		{"ubuntu-22.04", "ubuntu-24.04", true},
		{"ubuntu-24.04", "ubuntu-22.04", false},
		{"almalinux-9", "debian-12", true},
		{"debian-12", "ubuntu-24.04", true},
		{"abc123", "abc45", false},
		{"abc45", "abc123", true},
	}

	for _, tt := range tests {
		got := Less(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("Less(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
