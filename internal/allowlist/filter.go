// Package allowlist provides domain filtering with radix tree-based matching.
// This package is shared by both DNS and HTTP filters.
package allowlist

import (
	"strings"
	"sync"

	"github.com/armon/go-radix"

	"github.com/sandialabs/abox/internal/validation"
)

// Filter provides thread-safe domain filtering using a radix tree.
// Domains are stored in reversed form for efficient suffix matching.
type Filter struct {
	tree *radix.Tree
	mu   sync.RWMutex
}

// NewFilter creates a new empty filter.
func NewFilter() *Filter {
	return &Filter{
		tree: radix.New(),
	}
}

// ReverseDomain reverses the labels of a domain for radix tree storage.
// Example: "api.github.com." -> "com.github.api."
func ReverseDomain(name string) string {
	// Ensure trailing dot for FQDN
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	labels := splitDomainName(name)
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".") + "."
}

// splitDomainName splits a domain name into labels.
// This is a simplified version that doesn't depend on miekg/dns.
func splitDomainName(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// NormalizeDomain ensures consistent domain format (lowercase, trailing dot).
func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return domain
}

// Add adds a domain to the allowlist.
// Returns true if the domain was added, false if it already existed or was invalid.
func (f *Filter) Add(domain string) bool {
	domain = NormalizeDomain(domain)

	// Validate domain format for defense-in-depth
	if err := validation.ValidateDomain(strings.TrimSuffix(domain, ".")); err != nil {
		return false
	}

	key := ReverseDomain(domain)

	f.mu.Lock()
	defer f.mu.Unlock()

	_, exists := f.tree.Get(key)
	if exists {
		return false
	}
	f.tree.Insert(key, domain)
	return true
}

// Remove removes a domain from the allowlist.
// Returns true if the domain was removed, false if it didn't exist.
func (f *Filter) Remove(domain string) bool {
	domain = NormalizeDomain(domain)
	key := ReverseDomain(domain)

	f.mu.Lock()
	defer f.mu.Unlock()

	_, exists := f.tree.Delete(key)
	return exists
}

// IsAllowed checks if a domain (or any of its parent domains) is allowlisted.
// Example: If "github.com" is allowlisted, "api.github.com" is also allowed.
func (f *Filter) IsAllowed(domain string) bool {
	domain = NormalizeDomain(domain)
	key := ReverseDomain(domain)

	f.mu.RLock()
	defer f.mu.RUnlock()

	// LongestPrefix finds the longest matching prefix in the tree.
	// Since domains are reversed, this effectively matches the suffix.
	_, _, found := f.tree.LongestPrefix(key)
	return found
}

// List returns all allowlisted domains.
func (f *Filter) List() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var domains []string
	f.tree.Walk(func(key string, value any) bool {
		if domain, ok := value.(string); ok {
			domains = append(domains, domain)
		}
		return false // continue walking
	})
	return domains
}

// Count returns the number of allowlisted domains.
func (f *Filter) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.tree.Len()
}

// Clear removes all domains from the allowlist.
func (f *Filter) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tree = radix.New()
}

// Replace atomically replaces all domains with a new set.
// Invalid domains are silently skipped.
func (f *Filter) Replace(domains []string) {
	newTree := radix.New()
	for _, domain := range domains {
		domain = NormalizeDomain(domain)

		// Validate domain format for defense-in-depth
		if err := validation.ValidateDomain(strings.TrimSuffix(domain, ".")); err != nil {
			continue // Skip invalid domains
		}

		key := ReverseDomain(domain)
		newTree.Insert(key, domain)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.tree = newTree
}
