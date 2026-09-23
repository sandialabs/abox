// Package allowlist provides domain filtering with radix tree-based matching.
// This package is shared by both DNS and HTTP filters.
package allowlist

import (
	"strings"
	"sync"

	"github.com/armon/go-radix"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"

	"github.com/sandialabs/abox/internal/validation"
)

// idnaProfile converts Unicode/IDN domains to their ASCII (punycode) form so an
// allowlist entry typed in Unicode ("münchen.de") matches the punycode form DNS
// queries always arrive in ("xn--mnchen-3ya.de") — and vice versa. STD3 ASCII
// rules are relaxed so existing hostnames with underscores are unaffected, and
// Transitional processing is disabled for correct ß/ς handling.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// toASCIIDomain lowercases a bare domain (no trailing dot) and converts any IDN
// labels to punycode. On conversion error it returns the lowercased input
// unchanged, leaving downstream validation to reject it — never a hard failure.
func toASCIIDomain(domain string) string {
	domain = strings.ToLower(domain)
	if domain == "" {
		return domain
	}
	if ascii, err := idnaProfile.ToASCII(domain); err == nil {
		return ascii
	}
	return domain
}

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
	// Split on DNS presentation-format label boundaries (miekg/dns) rather than
	// literal ".", so an escaped dot inside a label ("evil\.github.com.") stays a
	// single label. A naive dot-split creates a matcher differential against how
	// resolvers parse the same name, which could let a crafted label be reversed
	// into a radix key that matches an allowlisted suffix it is not a subdomain of.
	labels := dns.SplitDomainName(name)
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".") + "."
}

// NormalizeDomain ensures consistent domain format (lowercase, punycode ASCII,
// trailing dot) so allowlist entries and DNS/HTTP lookups compare identically
// regardless of IDN vs. ASCII form.
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = toASCIIDomain(strings.TrimSuffix(domain, "."))
	return domain + "."
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
