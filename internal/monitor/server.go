package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/logutil"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

const (
	// maxLogEventSize is the maximum size of a single event to write to the log (1MB).
	// Events larger than this are rejected to prevent unbounded memory allocation.
	maxLogEventSize = 1024 * 1024
)

// Server manages the monitor daemon, reading from virtio-serial and providing RPC.
type Server struct {
	rpc.UnimplementedMonitorServer

	socketPath    string // virtio-serial socket from libvirt
	rpcSocketPath string // RPC socket for client connections
	logPath       string // path to event log file

	logWriter    *logutil.RotateWriter
	logMu        sync.Mutex // protects logWriter
	eventsLogged atomic.Uint64
	startTime    time.Time
	shutdown     chan struct{}
	grpcServer   *grpc.Server
	stopOnce     sync.Once
}

// NewServer creates a new monitor server.
func NewServer(socketPath, rpcSocketPath, logPath string) *Server {
	return &Server{
		socketPath:    socketPath,
		rpcSocketPath: rpcSocketPath,
		logPath:       logPath,
		shutdown:      make(chan struct{}),
		startTime:     time.Now(),
	}
}

// Start starts the monitor server, reading events and providing RPC.
func (s *Server) Start(ctx context.Context) error {
	// Open log file with rotation
	writer, err := logutil.NewRotateWriter(s.logPath, logutil.DefaultRotateConfig())
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	s.logWriter = writer

	// Start RPC server with UID verification for defense-in-depth.
	// This ensures only the same user who started the daemon can control it,
	// even if socket permissions were somehow modified.
	listener, err := rpc.UnixListenWithStaleAndUIDCheck(s.rpcSocketPath, getUID())
	if err != nil {
		s.closeLogWriter()
		return fmt.Errorf("failed to listen on RPC socket: %w", err)
	}

	s.grpcServer = grpc.NewServer()
	rpc.RegisterMonitorServer(s.grpcServer, s)

	// Start gRPC server in background
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			logging.Warn("monitor gRPC server stopped", "error", err)
		}
	}()

	logging.Debug("monitor RPC server started", "socket", s.rpcSocketPath)

	// Connect to virtio-serial and start reading events
	go s.readLoop(ctx)

	return nil
}

// getUID returns the current user ID.
func getUID() int {
	// Import os here would create a cycle, use syscall
	return syscall.Getuid()
}

// readLoop continuously reads from the virtio-serial socket and logs events.
func (s *Server) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		default:
		}

		// Connect to virtio-serial socket with retry
		mon, err := ConnectWithRetry(ctx, s.socketPath, time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logging.Debug("failed to connect to monitor socket", "error", err)
			time.Sleep(time.Second)
			continue
		}

		logging.Debug("connected to virtio-serial socket", "path", s.socketPath)

		// Read events until error or shutdown
		s.processEvents(ctx, mon)
		_ = mon.Close()

		// Brief pause before reconnecting
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// processEvents reads events from the monitor and writes them to the log.
func (s *Server) processEvents(ctx context.Context, mon *Monitor) {
	events := mon.Events(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if err := s.logEvent(event); err != nil {
				logging.Debug("failed to log event", "error", err)
			}
		}
	}
}

// logEvent writes an event to the log file.
func (s *Server) logEvent(event *Event) error {
	// Marshal event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Reject oversized events to prevent unbounded memory allocation
	if len(data) > maxLogEventSize {
		return fmt.Errorf("event too large: %d bytes (max %d)", len(data), maxLogEventSize)
	}

	// Write with newline (logutil.RotateWriter handles rotation and thread-safety)
	if _, err := s.logWriter.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	s.eventsLogged.Add(1)
	return nil
}

// closeLogWriter closes the log writer.
func (s *Server) closeLogWriter() {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if s.logWriter != nil {
		if err := s.logWriter.Close(); err != nil {
			logging.Warn("failed to close log writer", "error", err)
		}
		s.logWriter = nil
	}
}

// Stop stops the monitor server.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.shutdown)
		if s.grpcServer != nil {
			s.grpcServer.GracefulStop()
		}
		s.closeLogWriter()
		if err := os.Remove(s.rpcSocketPath); err != nil && !os.IsNotExist(err) {
			logging.Warn("failed to remove RPC socket", "path", s.rpcSocketPath, "error", err)
		}
	})
}

// Status implements the Monitor RPC service.
func (s *Server) Status(ctx context.Context, req *rpc.Empty) (*rpc.MonitorStatus, error) {
	logging.Audit("monitor status requested", "action", logging.ActionMonitorStatus, "socket", s.rpcSocketPath)

	var logSize int64
	s.logMu.Lock()
	if s.logWriter != nil {
		logSize = s.logWriter.Size()
	}
	s.logMu.Unlock()

	uptime := time.Since(s.startTime).Round(time.Second)

	return &rpc.MonitorStatus{
		Running:      true,
		EventsLogged: s.eventsLogged.Load(),
		LogFile:      s.logPath,
		LogSizeBytes: logSize,
		Uptime:       uptime.String(),
	}, nil
}

// Shutdown implements the Monitor RPC service.
func (s *Server) Shutdown(ctx context.Context, req *rpc.Empty) (*rpc.Empty, error) {
	logging.Audit("monitor shutdown requested", "action", logging.ActionMonitorShutdown, "socket", s.rpcSocketPath)

	// Stop in background to allow RPC response to be sent
	go s.Stop()
	return &rpc.Empty{}, nil
}

// Client provides methods for connecting to the monitor daemon.
type Client struct {
	conn   *grpc.ClientConn
	client rpc.MonitorClient
}

// Dial connects to the monitor daemon RPC socket.
func Dial(socketPath string) (*Client, error) {
	conn, err := rpc.UnixDial(socketPath)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:   conn,
		client: rpc.NewMonitorClient(conn),
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// RPCClient returns the underlying RPC client.
func (c *Client) RPCClient() rpc.MonitorClient {
	return c.client
}

// ClientContext returns a context with a timeout suitable for monitor RPC calls.
func ClientContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout.MonitorClient)
}
