// Package filterbase provides shared infrastructure for DNS and HTTP filter servers.
package filterbase

import (
	"github.com/sandialabs/abox/internal/logging"
)

// TrafficLoggerMixin provides shared traffic logging functionality for filter servers.
// Embed this in DNS and HTTP servers to avoid code duplication.
type TrafficLoggerMixin struct {
	trafficLog logging.TrafficLoggerInterface
}

// InitTrafficLogger initializes the traffic logger for this server.
func (m *TrafficLoggerMixin) InitTrafficLogger(logPath, filterType string) error {
	logger, err := logging.NewTrafficLogger(logPath, filterType)
	if err != nil {
		return err
	}
	m.trafficLog = logger
	return nil
}

// CloseTrafficLogger closes the traffic logger.
func (m *TrafficLoggerMixin) CloseTrafficLogger() {
	if m.trafficLog != nil {
		_ = m.trafficLog.Close()
		m.trafficLog = nil
	}
}

// TrafficLogger returns the traffic logger for use in request handlers.
func (m *TrafficLoggerMixin) TrafficLogger() logging.TrafficLoggerInterface {
	return m.trafficLog
}
