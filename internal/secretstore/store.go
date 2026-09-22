// Package secretstore provides a per-instance, host-side store for secret
// values (e.g. API keys) that the HTTP proxy injects into outbound requests.
//
// The store is a plain-text file at 0600 under the instance directory — the same
// trust level as the instance's SSH private key and MITM CA key. It is never
// copied into the guest. Values are base64-encoded on disk only so arbitrary
// secret bytes stay on a single line; base64 is encoding, NOT encryption.
package secretstore

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

// maxLineBytes bounds a single base64-encoded store line. The default
// bufio.Scanner cap is 64KB, which a large secret (e.g. a certificate bundle)
// can exceed; without this the daemon would fail to start and the store would
// become unmanageable. 8MB is far above any realistic credential.
const maxLineBytes = 8 << 20

// Store is a per-instance secret store backed by a single file.
type Store struct {
	path string
}

// New returns a Store backed by the file at path (typically Paths.Secrets).
func New(path string) *Store {
	return &Store{path: path}
}

// Load reads all secrets from the store. A missing file is not an error: it
// returns an empty map so callers (the daemon) can start with no secrets set.
func (s *Store) Load() (map[string]string, error) {
	// O_NOFOLLOW gives atomic symlink protection on the final path component.
	file, err := allowlist.OpenFileNoFollow(s.path, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("failed to open secrets file: %w", err)
	}
	defer file.Close()

	// The store holds plaintext secrets; warn if it is group/other-accessible so a
	// loosened file (bad restore, manual edit) is visible rather than silent.
	if info, statErr := file.Stat(); statErr == nil && info.Mode().Perm()&0o077 != 0 {
		logging.Warn("secrets file is group/other-accessible; tighten to 0600", "path", s.path, "mode", info.Mode().Perm())
	}

	out := map[string]string{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for scanner.Scan() {
		// Trim only a trailing CR (CRLF files); do NOT TrimSpace, which would eat
		// the delimiter space of an empty-valued line ("key ") and drop the entry.
		line := strings.TrimRight(scanner.Text(), "\r")
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, enc, ok := strings.Cut(line, " ")
		if !ok {
			continue // malformed line: skip rather than fail the whole daemon
		}
		if validation.ValidateSecretKey(key) != nil {
			continue
		}
		val, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			continue
		}
		out[key] = string(val)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading secrets file: %w", err)
	}
	return out, nil
}

// List returns the sorted key names in the store. It never returns values.
func (s *Store) List() ([]string, error) {
	m, err := s.Load()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Set stores value under key, replacing any existing value, and persists the
// whole store atomically (temp file + rename).
func (s *Store) Set(key, value string) error {
	if err := validation.ValidateSecretKey(key); err != nil {
		return err
	}
	m, err := s.Load()
	if err != nil {
		return err
	}
	m[key] = value
	return s.write(m)
}

// Delete removes key from the store. It is not an error if key is absent.
func (s *Store) Delete(key string) error {
	if err := validation.ValidateSecretKey(key); err != nil {
		return err
	}
	m, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := m[key]; !ok {
		return nil
	}
	delete(m, key)
	return s.write(m)
}

// write persists the full map atomically. It writes a temp file in the same
// directory at 0600, then renames over the destination. Rename replaces a
// symlink destination with the regular file rather than following it.
func (s *Store) write(m map[string]string) error {
	if err := allowlist.EnsureDir(s.path); err != nil {
		return fmt.Errorf("failed to prepare secrets directory: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp secrets file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	defer func() { _ = os.Remove(tmpName) }()

	// os.CreateTemp already yields 0600, but set it explicitly to be robust
	// against a permissive umask on some platforms.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set secrets file permissions: %w", err)
	}

	// Deterministic order keeps the file diff-stable and tests simple.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	w := bufio.NewWriter(tmp)
	for _, k := range keys {
		enc := base64.StdEncoding.EncodeToString([]byte(m[k]))
		if _, err := fmt.Fprintf(w, "%s %s\n", k, enc); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("failed to write secret: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to flush secrets file: %w", err)
	}
	// fsync before rename so a host crash can't leave a torn/empty file that
	// Load() would silently read as "no secrets" (dropping the credential).
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync secrets file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp secrets file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("failed to replace secrets file: %w", err)
	}
	return nil
}
