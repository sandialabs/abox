package monitor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sandialabs/abox/internal/logging"
)

const (
	// eventChannelBuffer is the number of events buffered before blocking.
	eventChannelBuffer = 100

	// maxEventSize is the maximum size of a single Tetragon event (1MB).
	maxEventSize = 1024 * 1024

	// initialScanBuffer is the initial buffer size for the scanner (64KB).
	initialScanBuffer = 64 * 1024

	// dialTimeout is the timeout for connecting to the Unix socket.
	dialTimeout = 5 * time.Second
)

// Monitor reads Tetragon events from the virtio-serial Unix socket.
type Monitor struct {
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

// connect opens a connection to the virtio-serial Unix socket.
// The socket is created by libvirt when the VM starts with monitoring enabled.
func connect(socketPath string) (*Monitor, error) {
	// Directly dial without pre-checking socket existence to avoid TOCTOU race.
	// The dial will fail with a clear error if the socket doesn't exist.
	conn, err := net.DialTimeout("unix", socketPath, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to monitor socket %s: %w", socketPath, err)
	}

	logging.Debug("connected to monitor socket", "path", socketPath)

	return &Monitor{
		conn: conn,
	}, nil
}

// ConnectWithRetry attempts to connect to the socket with retries.
// This is useful when waiting for the VM to start.
func ConnectWithRetry(ctx context.Context, socketPath string, interval time.Duration) (*Monitor, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			mon, err := connect(socketPath)
			if err == nil {
				return mon, nil
			}
			logging.Debug("waiting for monitor socket", "path", socketPath, "error", err)
		}
	}
}

// Close closes the connection to the socket.
func (m *Monitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	if m.conn != nil {
		return m.conn.Close()
	}
	return nil
}

// Events returns a channel that receives parsed events.
// The channel is closed when the connection is closed or an error occurs.
// Errors are logged but not returned; check the channel close for completion.
func (m *Monitor) Events(ctx context.Context) <-chan *Event {
	events := make(chan *Event, eventChannelBuffer)

	go func() {
		defer close(events)

		scanner := bufio.NewScanner(m.conn)
		// Tetragon events can be large
		scanner.Buffer(make([]byte, 0, initialScanBuffer), maxEventSize)

		m.scanEvents(ctx, scanner, events)
	}()

	return events
}

// scanEvents reads lines from the scanner, parses them into events, and sends
// them on the channel until the scanner is exhausted or the context is cancelled.
func (m *Monitor) scanEvents(ctx context.Context, scanner *bufio.Scanner, events chan<- *Event) {
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		event := parseLineToEvent(scanner.Bytes())
		if event == nil {
			continue
		}

		select {
		case events <- event:
		case <-ctx.Done():
			return
		}
	}

	m.logScannerError(scanner.Err())
}

// parseLineToEvent parses a single scanner line into an Event.
// Returns nil if the line is empty, unparseable, or intentionally skipped.
func parseLineToEvent(line []byte) *Event {
	if len(line) == 0 {
		return nil
	}

	event, err := ParseTetragonEvent(line)
	if err != nil {
		logging.Debug("failed to parse tetragon event", "error", err)
		return nil
	}
	return event
}

// logScannerError logs a scanner error if the monitor has not been intentionally closed.
func (m *Monitor) logScannerError(err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()

	if !closed {
		logging.Warn("monitor scanner error", "error", err)
	}
}

// IsAvailable checks if the monitor socket exists (without connecting).
func IsAvailable(socketPath string) bool {
	info, err := os.Stat(socketPath)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}
