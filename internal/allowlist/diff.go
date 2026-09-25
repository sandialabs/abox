package allowlist

import (
	"errors"
	"os"
	"sort"
	"strings"
)

// DomainSet returns the normalized set of domains a []string declares. Each
// entry is reduced to the canonical form used by the file parser (wildcard
// prefix stripped, trailing dot removed, lowercased, punycode) so two
// declarations that differ only in comments, ordering, or wildcard/IDN spelling
// compare as equal. Blank entries are skipped.
func DomainSet(domains []string) map[string]bool {
	set := make(map[string]bool, len(domains))
	for _, d := range domains {
		if strings.TrimSpace(d) == "" {
			continue
		}
		set[canonicalAllowlistEntry(d)] = true
	}
	return set
}

// LoadDomainSet reads path with the same parsing rules as the allowlist loader
// and returns its normalized domain set. A missing file returns an empty set
// (not an error), so comparing against a not-yet-created allowlist behaves like
// an empty on-disk state.
func LoadDomainSet(path string) (map[string]bool, error) {
	domains, err := parseAllowlistFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	return DomainSet(domains), nil
}

// DomainSetsEqual reports whether two normalized domain sets contain exactly the
// same domains.
func DomainSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// RenderDomainSet renders a domain set as sorted, one-per-line text, suitable
// for a human-readable diff of two allowlists (e.g. the reconcile diff view). It
// lives next to DomainSet so the set representation and its rendering stay
// together.
func RenderDomainSet(set map[string]bool) string {
	domains := make([]string, 0, len(set))
	for d := range set {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	var sb strings.Builder
	for _, d := range domains {
		sb.WriteString(d)
		sb.WriteString("\n")
	}
	return sb.String()
}
