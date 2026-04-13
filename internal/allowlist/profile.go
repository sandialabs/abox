package allowlist

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

// ProfileLogger captures and deduplicates domains for profile building.
type ProfileLogger struct {
	domains map[string]time.Time // domain -> first seen
	mu      sync.RWMutex
	file    *os.File
	path    string
}

// NewProfileLogger creates a new ProfileLogger that persists to the given path.
func NewProfileLogger(path string) (*ProfileLogger, error) {
	p := &ProfileLogger{
		domains: make(map[string]time.Time),
		path:    path,
	}

	// Load existing domains from file (uses O_NOFOLLOW for symlink protection)
	if err := p.loadFromFile(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// Open file for appending with O_NOFOLLOW for atomic TOCTOU protection
	f, err := OpenFileNoFollow(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	p.file = f

	return p, nil
}

// loadFromFile loads existing domains from the profile log file.
func (p *ProfileLogger) loadFromFile() error {
	// Use O_NOFOLLOW for symlink protection
	f, err := OpenFileNoFollow(p.path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "timestamp source domain"
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue // Skip malformed lines
		}
		ts, err := time.Parse(time.RFC3339, parts[0])
		if err != nil {
			continue // Skip lines with invalid timestamp
		}
		domain := parts[2]
		// Validate domain has no control characters
		if containsControlChars(domain) {
			continue
		}
		if _, exists := p.domains[domain]; !exists {
			p.domains[domain] = ts
		}
	}
	return scanner.Err()
}

// containsControlChars checks if a string contains control characters.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 32 || r == 127 {
			return true
		}
	}
	return false
}

// LogDomain logs a domain if not already seen. Thread-safe and deduplicates.
// The source parameter indicates where the domain came from (e.g., "DNS" or "HTTP").
func (p *ProfileLogger) LogDomain(source, domain string) {
	// Normalize: lowercase and remove trailing dot
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return
	}

	// Reject domains with control characters (security: prevents log injection)
	if containsControlChars(domain) {
		return
	}

	// Reject domains with newlines (prevents log injection)
	if strings.ContainsAny(domain, "\r\n") {
		return
	}

	// Validate source has no control characters or whitespace
	if containsControlChars(source) || strings.ContainsAny(source, " \t\r\n") {
		source = "UNKNOWN"
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.domains[domain]; exists {
		return
	}

	now := time.Now()
	p.domains[domain] = now

	// Append to file (log errors but don't fail - logging is best-effort)
	// Format: "timestamp source domain"
	if p.file != nil {
		line := now.Format(time.RFC3339) + " " + source + " " + domain + "\n"
		if _, err := p.file.WriteString(line); err != nil {
			// Log error but continue - domain is still in memory
			logging.Warn("failed to write domain to profile log", "error", err)
			return
		}
		if err := p.file.Sync(); err != nil {
			logging.Warn("failed to sync profile log", "error", err)
		}
	}
}

// GetDomains returns all captured domains sorted alphabetically.
func (p *ProfileLogger) GetDomains() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domains := make([]string, 0, len(p.domains))
	for d := range p.domains {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

// Count returns the number of unique domains captured.
func (p *ProfileLogger) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.domains)
}

// Clear removes all captured domains and truncates the log file.
// The mutex is held for the entire operation to prevent races with LogDomain.
func (p *ProfileLogger) Clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.domains = make(map[string]time.Time)

	// Close and reopen atomically while holding mutex to prevent race
	if p.file != nil {
		if err := p.file.Close(); err != nil {
			logging.Warn("failed to close profile log", "error", err)
		}
		p.file = nil // Mark as nil before reopen
	}

	// Use O_NOFOLLOW for atomic symlink protection (no TOCTOU race)
	f, err := OpenFileNoFollow(p.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	p.file = f
	return nil
}

// ExportAsAllowlist returns captured domains formatted as an allowlist.
func (p *ProfileLogger) ExportAsAllowlist() string {
	domains := p.GetDomains()
	if len(domains) == 0 {
		return "# No domains captured\n"
	}

	var sb strings.Builder
	sb.WriteString("# Captured domains from profile mode\n")
	sb.WriteString("# Generated: " + time.Now().Format(time.RFC3339) + "\n\n")

	for _, d := range domains {
		sb.WriteString(d + "\n")
	}

	return sb.String()
}

// Close closes the profile logger and its file.
func (p *ProfileLogger) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.file != nil {
		return p.file.Close()
	}
	return nil
}
