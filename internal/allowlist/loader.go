package allowlist

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

// Loader handles loading and watching the allowlist configuration file.
type Loader struct {
	path     string
	filter   *Filter
	watcher  *fsnotify.Watcher
	onReload func(count int, err error)
	stopCh   chan struct{}
	sighup   chan os.Signal
}

// NewLoader creates a new configuration loader.
func NewLoader(path string, filter *Filter) *Loader {
	return &Loader{
		path:   path,
		filter: filter,
		stopCh: make(chan struct{}),
	}
}

// SetReloadCallback sets a callback to be called after each reload.
func (l *Loader) SetReloadCallback(fn func(count int, err error)) {
	l.onReload = fn
}

// Load loads domains from the configuration file into the filter.
func (l *Loader) Load() error {
	domains, err := l.parseFile()
	if err != nil {
		return err
	}

	l.filter.Replace(domains)

	logging.Debug("allowlist reloaded", "count", len(domains), "path", l.path)

	if l.onReload != nil {
		l.onReload(len(domains), nil)
	}

	return nil
}

// parseFile reads and parses the loader's allowlist file.
func (l *Loader) parseFile() ([]string, error) {
	return parseAllowlistFile(l.path)
}

// parseAllowlistFile reads and parses an allowlist file into its normalized,
// validated domains. It needs no Loader or Filter, so callers that only want the
// file's contents (e.g. LoadDomainSet) can reuse it directly.
// Supports wildcard syntax: *.domain.com (equivalent to domain.com).
func parseAllowlistFile(path string) ([]string, error) {
	// Use O_NOFOLLOW for atomic symlink protection (prevents TOCTOU race)
	file, err := OpenFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open allowlist file: %w", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize (strip "*." wildcard prefix, punycode) so a Unicode allowlist
		// line matches the ASCII form DNS queries arrive in. The radix tree matches
		// subdomains, so stripping the wildcard prefix is equivalent.
		line = canonicalAllowlistEntry(line)

		// Validate domain format (skip invalid entries silently)
		if err := validation.ValidateDomain(line); err != nil {
			continue
		}

		domains = append(domains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading allowlist file: %w", err)
	}

	return domains, nil
}

// canonicalAllowlistEntry reduces a raw allowlist line (or a bare domain) to the
// canonical form used for storage and comparison: wildcard prefix stripped,
// trailing dot removed, lowercased, and IDN converted to punycode. Shared by the
// file parser, RemoveDomain's line matching, and the domain-set helpers so all
// three normalize identically.
func canonicalAllowlistEntry(domain string) string {
	domain = strings.TrimPrefix(strings.TrimSpace(domain), "*.")
	return toASCIIDomain(strings.TrimSuffix(domain, "."))
}

// Watch starts watching the configuration file for changes.
// It also handles SIGHUP for manual reload triggers.
func (l *Loader) Watch() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	l.watcher = watcher

	// Watch the directory containing the config file
	// (watching the file directly can miss some editors' save operations)
	dir := filepath.Dir(l.path)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("failed to watch config directory: %w", err)
	}

	// Set up the manual reload signal handler (SIGHUP on Unix; no-op on
	// platforms without it, where l.sighup is nil and the select case below
	// simply never fires).
	l.sighup = registerReloadSignal()

	go l.watchLoop(l.sighup)

	return nil
}

// watchLoop handles file change events and SIGHUP signals.
func (l *Loader) watchLoop(sighup chan os.Signal) {
	filename := filepath.Base(l.path)

	for {
		select {
		case <-l.stopCh:
			return

		case <-sighup:
			// A value on this channel is always the reload signal (the channel
			// is registered for it specifically). On platforms without the
			// signal, sighup is nil and this case never fires.
			if err := l.Load(); err != nil && l.onReload != nil {
				l.onReload(0, err)
			}

		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			l.handleWatcherEvent(event, filename)

		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			logging.Debug("allowlist watcher error", "error", err)
			if l.onReload != nil {
				l.onReload(0, fmt.Errorf("watcher error: %w", err))
			}
		}
	}
}

// handleWatcherEvent processes a single fsnotify event, reloading if our file was modified.
func (l *Loader) handleWatcherEvent(event fsnotify.Event, filename string) {
	if filepath.Base(event.Name) != filename {
		return
	}
	if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
		if err := l.Load(); err != nil && l.onReload != nil {
			l.onReload(0, err)
		}
	}
}

// Stop stops the file watcher.
func (l *Loader) Stop() {
	close(l.stopCh)
	stopReloadSignal(l.sighup)
	if l.watcher != nil {
		_ = l.watcher.Close()
	}
}

// EnsureDir creates the configuration directory if it doesn't exist.
// Uses restrictive permissions (0o700) to protect sensitive allowlist data.
// Also fixes permissions on existing directories if they are too permissive.
func EnsureDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// Check and fix permissions on existing directory
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		// Directory is world or group readable/writable, fix it
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // 0o700 is intentional: owner-only access for security
			return fmt.Errorf("failed to fix directory permissions: %w", err)
		}
	}
	return nil
}

// SaveDomain appends a domain to the configuration file.
func (l *Loader) SaveDomain(domain string) error {
	domain = strings.TrimSpace(domain)

	// Reject newlines explicitly (defense-in-depth against injection)
	if strings.ContainsAny(domain, "\r\n") {
		return errors.New("invalid domain: contains newline characters")
	}

	// Validate domain format before saving
	if err := validation.ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}

	// Use OpenFileNoFollow for atomic symlink protection
	file, err := OpenFileNoFollow(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open allowlist file for writing: %w", err)
	}

	// Append newline (domain already validated to not contain newlines)
	if _, err := file.WriteString(domain + "\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write domain: %w", err)
	}

	// Explicitly close to check for flush errors
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to flush domain write: %w", err)
	}

	return nil
}

// RemoveDomain atomically rewrites the configuration file, dropping any line
// whose domain (after stripping the "*." wildcard prefix and normalizing to
// ASCII) matches domain. Comments, blank lines, ordering, and every other entry
// are preserved — each kept line is re-emitted newline-terminated, so a file
// whose final line lacked a trailing newline gains one (the only rewrite that is
// not byte-for-byte). It is the persistence counterpart to SaveDomain, so a
// removal survives a later Load()/reload instead of being resurrected from a
// stale file.
//
// Returns (true, nil) if at least one line was removed, (false, nil) if no line
// matched (not an error — mirrors Filter.Remove's bool semantics so API callers
// can still distinguish "not found").
func (l *Loader) RemoveDomain(domain string) (bool, error) {
	// Normalize the target the same way the parser normalizes stored lines, so
	// "*.GitHub.com" on disk matches a remove of "github.com" and vice versa.
	target := canonicalAllowlistEntry(domain)

	// Read existing lines with symlink protection (matches parseFile/SaveDomain).
	file, err := OpenFileNoFollow(l.path, os.O_RDONLY, 0)
	if err != nil {
		return false, fmt.Errorf("failed to open allowlist file: %w", err)
	}

	var kept []string
	removed := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		// Comments and blank lines are never candidates; keep them verbatim.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			kept = append(kept, raw)
			continue
		}

		if canonicalAllowlistEntry(trimmed) == target {
			removed = true
			continue // drop this line
		}
		kept = append(kept, raw)
	}
	if err := scanner.Err(); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("error reading allowlist file: %w", err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("failed to close allowlist file: %w", err)
	}

	// Nothing matched: leave the file untouched (avoids a needless rewrite and a
	// spurious fsnotify reload event).
	if !removed {
		return false, nil
	}

	if err := l.atomicWriteLines(kept); err != nil {
		return false, err
	}
	return true, nil
}

// atomicWriteLines writes lines (each newline-terminated) to l.path atomically:
// a temp file in the same directory at 0600, fsync, then rename over the
// destination. Rename replaces a symlink destination with the regular file
// rather than following it (mirrors internal/secretstore's write()).
func (l *Loader) atomicWriteLines(lines []string) error {
	dir := filepath.Dir(l.path)
	tmp, err := os.CreateTemp(dir, ".allowlist-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp allowlist file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	defer func() { _ = os.Remove(tmpName) }()

	// os.CreateTemp already yields 0600, but set it explicitly to be robust
	// against a permissive umask on some platforms.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set allowlist file permissions: %w", err)
	}

	w := bufio.NewWriter(tmp)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("failed to write allowlist line: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to flush allowlist file: %w", err)
	}
	// fsync before rename so a host crash can't leave a torn/empty file that
	// Load() would silently read as an empty allowlist.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync allowlist file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp allowlist file: %w", err)
	}
	if err := os.Rename(tmpName, l.path); err != nil {
		return fmt.Errorf("failed to replace allowlist file: %w", err)
	}
	return nil
}
