package logging

import (
	"encoding/json"
	"time"

	"github.com/sandialabs/abox/internal/logutil"
)

// TrafficEvent represents a filter traffic event for logging.
type TrafficEvent struct {
	Time   string `json:"time"`             // RFC3339 timestamp
	Action string `json:"action"`           // "allow" or "block"
	Domain string `json:"domain"`           // domain name
	Type   string `json:"type,omitempty"`   // DNS query type (A, AAAA, etc.) or empty for HTTP
	Reason string `json:"reason,omitempty"` // block reason (not_in_allowlist, ssrf, domain_fronting)
	Source string `json:"source,omitempty"` // source IP address
	Method string `json:"method,omitempty"` // HTTP method (for HTTP logs)
	URL    string `json:"url,omitempty"`    // URL (for HTTP logs)
}

// TrafficLogger logs filter allow/block decisions to a rotating log file.
type TrafficLogger struct {
	writer *logutil.RotateWriter
	filter string // "dns" or "http" for context
}

// NewTrafficLogger creates a new traffic logger for the specified filter.
func NewTrafficLogger(logPath, filter string) (*TrafficLogger, error) {
	writer, err := logutil.NewRotateWriter(logPath, logutil.DefaultRotateConfig())
	if err != nil {
		return nil, err
	}

	return &TrafficLogger{
		writer: writer,
		filter: filter,
	}, nil
}

// LogAllow logs an allowed request.
func (t *TrafficLogger) LogAllow(domain, source string, opts ...EventOption) {
	event := TrafficEvent{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Action: "allow",
		Domain: domain,
		Source: source,
	}

	// Apply options
	for _, opt := range opts {
		opt(&event)
	}

	t.writeEvent(event)
}

// LogBlock logs a blocked request.
func (t *TrafficLogger) LogBlock(domain, reason, source string, opts ...EventOption) {
	event := TrafficEvent{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Action: "block",
		Domain: domain,
		Reason: reason,
		Source: source,
	}

	// Apply options
	for _, opt := range opts {
		opt(&event)
	}

	t.writeEvent(event)
}

// writeEvent writes an event to the log file.
func (t *TrafficLogger) writeEvent(event TrafficEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		Warn("failed to marshal traffic event", "error", err, "filter", t.filter, "domain", event.Domain)
		return
	}

	// Write with newline
	data = append(data, '\n')
	if _, err := t.writer.Write(data); err != nil {
		Warn("failed to write traffic event", "error", err, "filter", t.filter, "domain", event.Domain)
	}
}

// Sync flushes the traffic log to disk.
func (t *TrafficLogger) Sync() error {
	if t.writer != nil {
		return t.writer.Sync()
	}
	return nil
}

// Close closes the traffic logger.
func (t *TrafficLogger) Close() error {
	if t.writer != nil {
		return t.writer.Close()
	}
	return nil
}

// TrafficLoggerInterface defines the interface for traffic logging.
// Exported for use by dnsfilter and httpfilter packages.
type TrafficLoggerInterface interface {
	LogAllow(domain, source string, opts ...EventOption)
	LogBlock(domain, reason, source string, opts ...EventOption)
	Close() error
}

// EventOption is a functional option for configuring traffic events.
type EventOption func(*TrafficEvent)

// WithType sets the DNS query type.
func WithType(qtype string) EventOption {
	return func(e *TrafficEvent) {
		e.Type = qtype
	}
}

// WithMethod sets the HTTP method.
func WithMethod(method string) EventOption {
	return func(e *TrafficEvent) {
		e.Method = method
	}
}

// WithURL sets the HTTP URL.
func WithURL(url string) EventOption {
	return func(e *TrafficEvent) {
		e.URL = url
	}
}
