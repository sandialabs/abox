package allowlist

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/unix"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

// OpenFileNoFollow opens a file with O_NOFOLLOW to prevent symlink attacks.
// This provides atomic TOCTOU protection - the check and open happen in one syscall.
func OpenFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flag|unix.O_NOFOLLOW, uint32(perm))
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("path is a symlink (security risk): %s", path)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil //nolint:gosec // fd comes from unix.Open, safe conversion
}

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

// parseFile reads and parses the allowlist file.
// Supports wildcard syntax: *.domain.com (equivalent to domain.com)
func (l *Loader) parseFile() ([]string, error) {
	// Use O_NOFOLLOW for atomic symlink protection (prevents TOCTOU race)
	file, err := OpenFileNoFollow(l.path, os.O_RDONLY, 0)
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

		// Handle wildcard syntax: *.domain.com -> domain.com
		// The radix tree automatically matches subdomains, so we just
		// strip the wildcard prefix for storage
		line = strings.TrimPrefix(line, "*.")

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

	// Set up SIGHUP handler
	l.sighup = make(chan os.Signal, 1)
	signal.Notify(l.sighup, syscall.SIGHUP)

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

		case sig := <-sighup:
			if sig == syscall.SIGHUP {
				if err := l.Load(); err != nil && l.onReload != nil {
					l.onReload(0, err)
				}
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
	if l.sighup != nil {
		signal.Stop(l.sighup)
	}
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
