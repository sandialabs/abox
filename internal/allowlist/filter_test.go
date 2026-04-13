package allowlist

import (
	"sort"
	"sync"
	"testing"
)

func TestReverseDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "github.com", "com.github."},
		{"with-trailing-dot", "github.com.", "com.github."},
		{"subdomain", "api.github.com", "com.github.api."},
		{"deep-subdomain", "a.b.c.d.example.com", "com.example.d.c.b.a."},
		{"single-label", "localhost", "localhost."},
		{"tld-only", "com", "com."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReverseDomain(tt.input)
			if result != tt.expected {
				t.Errorf("ReverseDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "GITHUB.COM", "github.com."},
		{"mixed-case", "GitHub.Com", "github.com."},
		{"already-lowercase", "github.com", "github.com."},
		{"with-trailing-dot", "github.com.", "github.com."},
		{"whitespace", "  github.com  ", "github.com."},
		{"subdomain", "API.GITHUB.COM", "api.github.com."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFilter_Add_Remove(t *testing.T) {
	f := NewFilter()

	// Add should return true for new domain
	if !f.Add("github.com") {
		t.Error("Add(github.com) should return true for new domain")
	}

	// Add should return false for duplicate
	if f.Add("github.com") {
		t.Error("Add(github.com) should return false for duplicate")
	}

	// Add should normalize case
	if f.Add("GITHUB.COM") {
		t.Error("Add(GITHUB.COM) should return false (normalized duplicate)")
	}

	// Add should return false for invalid domain
	if f.Add("github\n.com") {
		t.Error("Add should return false for invalid domain with control char")
	}

	// Count should be 1
	if f.Count() != 1 {
		t.Errorf("Count() = %d, want 1", f.Count())
	}

	// Remove should return true for existing
	if !f.Remove("github.com") {
		t.Error("Remove(github.com) should return true")
	}

	// Remove should return false for non-existing
	if f.Remove("github.com") {
		t.Error("Remove(github.com) should return false (already removed)")
	}

	// Count should be 0
	if f.Count() != 0 {
		t.Errorf("Count() = %d, want 0", f.Count())
	}
}

func TestFilter_IsAllowed(t *testing.T) {
	f := NewFilter()
	f.Add("github.com")
	f.Add("example.org")

	tests := []struct {
		name    string
		domain  string
		allowed bool
	}{
		{"exact-match", "github.com", true},
		{"subdomain-match", "api.github.com", true},
		{"deep-subdomain-match", "a.b.c.github.com", true},
		{"not-allowed", "google.com", false},
		{"partial-match-not-allowed", "notgithub.com", false},
		{"subdomain-of-allowlisted", "test.example.org", true},
		{"case-insensitive", "GITHUB.COM", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.IsAllowed(tt.domain)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.domain, result, tt.allowed)
			}
		})
	}
}

func TestFilter_List(t *testing.T) {
	f := NewFilter()

	// Empty list
	list := f.List()
	if len(list) != 0 {
		t.Errorf("List() on empty filter = %v, want empty", list)
	}

	// Add some domains
	f.Add("github.com")
	f.Add("google.com")
	f.Add("example.org")

	list = f.List()
	if len(list) != 3 {
		t.Errorf("List() length = %d, want 3", len(list))
	}

	// Sort for consistent comparison
	sort.Strings(list)
	expected := []string{"example.org.", "github.com.", "google.com."}
	for i, domain := range list {
		if domain != expected[i] {
			t.Errorf("List()[%d] = %q, want %q", i, domain, expected[i])
		}
	}
}

func TestFilter_Clear(t *testing.T) {
	f := NewFilter()
	f.Add("github.com")
	f.Add("google.com")

	if f.Count() != 2 {
		t.Errorf("Count() before Clear() = %d, want 2", f.Count())
	}

	f.Clear()

	if f.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", f.Count())
	}

	if f.IsAllowed("github.com") {
		t.Error("IsAllowed(github.com) after Clear() should be false")
	}
}

func TestFilter_Replace(t *testing.T) {
	f := NewFilter()
	f.Add("github.com")
	f.Add("google.com")

	// Replace with new set
	f.Replace([]string{"example.org", "example.com"})

	if f.Count() != 2 {
		t.Errorf("Count() after Replace() = %d, want 2", f.Count())
	}

	// Old domains should not be allowed
	if f.IsAllowed("github.com") {
		t.Error("IsAllowed(github.com) after Replace() should be false")
	}

	// New domains should be allowed
	if !f.IsAllowed("example.org") {
		t.Error("IsAllowed(example.org) after Replace() should be true")
	}
}

func TestFilter_Concurrent(t *testing.T) {
	f := NewFilter()
	var wg sync.WaitGroup

	// Concurrent adds
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.Add("domain" + string(rune('a'+i%26)) + ".com")
		}(i)
	}

	// Concurrent reads
	for range 100 {
		wg.Go(func() {
			f.IsAllowed("github.com")
			f.List()
			f.Count()
		})
	}

	wg.Wait()

	// Should not panic and count should be reasonable
	count := f.Count()
	if count == 0 || count > 26 {
		t.Errorf("Count() = %d, expected between 1 and 26", count)
	}
}
