package allowlist

import (
	"sync"
	"sync/atomic"
)

const (
	// ModeActive is the string representation of active (blocking) mode.
	ModeActive = "active"
	// ModePassive is the string representation of passive (capturing) mode.
	ModePassive = "passive"
)

// ModeController manages active/passive mode state.
// Embed this in filter servers to avoid code duplication.
// In passive mode, domains are automatically captured to the profile log.
type ModeController struct {
	active     atomic.Bool
	profileLog *ProfileLogger
	profileMu  sync.RWMutex

	// Track the actual port we're listening on
	listenPort int
	portMu     sync.RWMutex
}

// InitProfileLogger initializes the profile logger for domain capture.
// This should be called at server startup. Once initialized, passive mode
// will automatically capture domains to the log.
func (m *ModeController) InitProfileLogger(path string) error {
	m.profileMu.Lock()
	defer m.profileMu.Unlock()

	if m.profileLog != nil {
		return nil // Already initialized
	}

	logger, err := NewProfileLogger(path)
	if err != nil {
		return err
	}
	m.profileLog = logger
	return nil
}

// SetActive sets the active/passive mode.
func (m *ModeController) SetActive(active bool) {
	m.active.Store(active)
}

// IsActive returns whether the server is in active (blocking) mode.
func (m *ModeController) IsActive() bool {
	return m.active.Load()
}

// GetMode returns the current mode as a string.
func (m *ModeController) GetMode() string {
	if m.IsActive() {
		return ModeActive
	}
	return ModePassive
}

// GetListenPort returns the actual port the server is listening on.
func (m *ModeController) GetListenPort() int {
	m.portMu.RLock()
	defer m.portMu.RUnlock()
	return m.listenPort
}

// SetListenPort sets the port the server is listening on.
func (m *ModeController) SetListenPort(port int) {
	m.portMu.Lock()
	defer m.portMu.Unlock()
	m.listenPort = port
}

// LogDomain logs a domain if in passive mode. Thread-safe.
// This should be called for every request; it only logs when not active.
func (m *ModeController) LogDomain(source, domain string) {
	if m.active.Load() {
		return // Don't log in active mode
	}

	m.profileMu.RLock()
	defer m.profileMu.RUnlock()

	if m.profileLog != nil {
		m.profileLog.LogDomain(source, domain)
	}
}

// GetProfileLogger returns the profile logger.
func (m *ModeController) GetProfileLogger() *ProfileLogger {
	m.profileMu.RLock()
	defer m.profileMu.RUnlock()
	return m.profileLog
}
