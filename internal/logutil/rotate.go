package logutil

import (
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"sync"
)

// syslogWriter is a package-level syslog writer for logging rotation errors.
// Initialized lazily via sync.Once to avoid data races.
var (
	syslogWriter *syslog.Writer
	syslogOnce   sync.Once
)

// logError logs an error message to syslog if available.
// Falls back silently if syslog is unavailable.
func logError(msg string, err error) {
	syslogOnce.Do(func() {
		w, sysErr := syslog.New(syslog.LOG_WARNING|syslog.LOG_USER, "abox-logutil")
		if sysErr != nil {
			return // syslog unavailable
		}
		syslogWriter = w
	})
	if syslogWriter != nil {
		_ = syslogWriter.Warning(fmt.Sprintf("%s: %v", msg, err))
	}
}

// Default rotation settings.
const (
	// DefaultMaxSize is the maximum size of a log file before rotation (10MB).
	DefaultMaxSize = 10 * 1024 * 1024

	// DefaultMaxBackups is the number of old log files to keep.
	DefaultMaxBackups = 3
)

// RotateConfig holds log rotation configuration.
type RotateConfig struct {
	MaxSize    int64 // bytes before rotation (default: 10MB)
	MaxBackups int   // rotated files to keep (default: 3)
}

// DefaultRotateConfig returns the default rotation configuration.
func DefaultRotateConfig() RotateConfig {
	return RotateConfig{
		MaxSize:    DefaultMaxSize,
		MaxBackups: DefaultMaxBackups,
	}
}

// RotateWriter is a thread-safe log writer with automatic rotation.
type RotateWriter struct {
	path   string
	config RotateConfig

	mu      sync.Mutex
	file    *os.File
	written int64 // bytes written since last rotation check
}

// NewRotateWriter creates a new rotating log writer.
// The log file is created if it doesn't exist.
func NewRotateWriter(path string, config RotateConfig) (*RotateWriter, error) {
	// Apply defaults for zero values
	if config.MaxSize <= 0 {
		config.MaxSize = DefaultMaxSize
	}
	if config.MaxBackups <= 0 {
		config.MaxBackups = DefaultMaxBackups
	}

	w := &RotateWriter{
		path:   path,
		config: config,
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

// Write implements io.Writer with automatic rotation.
func (w *RotateWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if rotation is needed
	if err := w.maybeRotate(); err != nil {
		return 0, fmt.Errorf("failed to rotate log: %w", err)
	}

	n, err = w.file.Write(p)
	w.written += int64(n)
	return n, err
}

// Close closes the log file.
func (w *RotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// Sync flushes the log file to disk.
func (w *RotateWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Sync()
	}
	return nil
}

// openFile opens the log file for appending.
func (w *RotateWriter) openFile() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}

	// Get current size for tracking
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	w.file = f
	w.written = info.Size()
	return nil
}

// isSymlink checks if a path is a symbolic link.
// Returns false if the path doesn't exist or on error.
func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}

// maybeRotate checks if log rotation is needed and performs it.
// Must be called with w.mu held.
func (w *RotateWriter) maybeRotate() error {
	if w.written < w.config.MaxSize {
		return nil
	}

	// Double-check actual file size (in case of external truncation)
	info, err := w.file.Stat()
	if err != nil {
		return err
	}
	if info.Size() < w.config.MaxSize {
		w.written = info.Size()
		return nil
	}

	// Security: check for symlink attacks on log files before rotation
	// An attacker could replace a log file with a symlink to overwrite arbitrary files
	if isSymlink(w.path) {
		return errors.New("refusing to rotate: log file is a symlink")
	}

	// Sync and close current log to ensure all data is written before rotation
	if err := w.file.Sync(); err != nil {
		logError("failed to sync log file before rotation", err)
	}
	if err := w.file.Close(); err != nil {
		logError("failed to close log file before rotation", err)
	}
	w.file = nil

	// Rotate existing backups (check for symlinks to prevent attacks)
	for i := w.config.MaxBackups - 1; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", w.path, i)
		newPath := fmt.Sprintf("%s.%d", w.path, i+1)

		// Security: refuse to rotate if either path is a symlink
		if isSymlink(oldPath) || isSymlink(newPath) {
			continue
		}

		if err := os.Rename(oldPath, newPath); err != nil && !os.IsNotExist(err) {
			logError("failed to rotate backup log file", err)
		}
	}

	// Security: check destination before moving current log
	newPath := w.path + ".1"
	if !isSymlink(newPath) {
		if err := os.Rename(w.path, newPath); err != nil && !os.IsNotExist(err) {
			logError("failed to rotate current log file", err)
		}
	}

	// Open new log file
	if err := w.openFile(); err != nil {
		return fmt.Errorf("failed to open new log file after rotation: %w", err)
	}

	w.written = 0
	return nil
}

// Size returns the current log file size.
func (w *RotateWriter) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0
	}

	info, err := w.file.Stat()
	if err != nil {
		return w.written
	}
	return info.Size()
}
