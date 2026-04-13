package dnsfilter

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/validation"
)

// Stats holds DNS server statistics.
type Stats struct {
	TotalQueries   uint64
	AllowedQueries uint64
	BlockedQueries uint64
	StartTime      time.Time
}

const (
	// ednsBufferSize is the EDNS0 UDP buffer size we advertise to clients.
	// 1232 is the DNS Flag Day recommended size to avoid UDP fragmentation.
	ednsBufferSize = 1232
)

// HealthcheckDomain is a sentinel domain that always responds regardless of mode or allowlist.
// This enables reliable troubleshooting and connectivity checks.
const HealthcheckDomain = "healthcheck.abox.local."

// Server handles DNS queries with filtering.
type Server struct {
	allowlist.ModeController      // embedded mode controller
	filterbase.TrafficLoggerMixin // embedded traffic logger
	filter                        *allowlist.Filter
	upstream                      string
	stats                         Stats
}

// NewServer creates a new DNS server.
func NewServer(filter *allowlist.Filter, upstream string, passive bool) (*Server, error) {
	// Validate and normalize upstream DNS server format
	normalizedUpstream, err := validation.NormalizeUpstreamDNS(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream DNS server: %w", err)
	}

	s := &Server{
		filter:   filter,
		upstream: normalizedUpstream,
		stats: Stats{
			StartTime: time.Now(),
		},
	}
	s.SetActive(!passive)
	return s, nil
}

// InitTrafficLogger initializes the traffic logger for this server.
func (s *Server) InitTrafficLogger(logPath string) error {
	return s.TrafficLoggerMixin.InitTrafficLogger(logPath, "dns")
}

// GetStats returns current statistics.
func (s *Server) GetStats() Stats {
	return Stats{
		TotalQueries:   atomic.LoadUint64(&s.stats.TotalQueries),
		AllowedQueries: atomic.LoadUint64(&s.stats.AllowedQueries),
		BlockedQueries: atomic.LoadUint64(&s.stats.BlockedQueries),
		StartTime:      s.stats.StartTime,
	}
}

// setEdns0 ensures the response has appropriate EDNS0 handling.
func setEdns0(resp *dns.Msg, req *dns.Msg) {
	reqOpt := req.IsEdns0()

	cleanExtra := make([]dns.RR, 0, len(resp.Extra))
	for _, rr := range resp.Extra {
		if _, ok := rr.(*dns.OPT); !ok {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	resp.Extra = cleanExtra

	if reqOpt == nil {
		return
	}

	resp.SetEdns0(ednsBufferSize, reqOpt.Do())
}

// buildCleanResponse creates a properly formatted DNS response from an upstream response.
// This avoids issues with Copy() corrupting OPT records and SetReply() copying flags incorrectly.
func buildCleanResponse(upstream *dns.Msg, req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)

	// Set response header - manually to avoid flag contamination
	resp.Id = req.Id
	resp.Response = true
	resp.Opcode = req.Opcode
	resp.Authoritative = upstream.Authoritative
	resp.Truncated = upstream.Truncated
	resp.RecursionDesired = req.RecursionDesired
	resp.RecursionAvailable = true               // We are a recursive resolver
	resp.Zero = false                            // explicitly set for protocol correctness
	resp.AuthenticatedData = false               // CRITICAL: Never copy AD flag unless we validate
	resp.CheckingDisabled = req.CheckingDisabled // CD can be echoed
	resp.Rcode = upstream.Rcode

	// Copy question section from original request (preserves case)
	resp.Question = req.Question

	// Copy answer sections - these don't need special handling
	resp.Answer = upstream.Answer
	resp.Ns = upstream.Ns

	// Copy Extra but filter out OPT records (we'll add our own)
	for _, rr := range upstream.Extra {
		if _, ok := rr.(*dns.OPT); !ok {
			resp.Extra = append(resp.Extra, rr)
		}
	}

	resp.Compress = true
	return resp
}

// prepareResponse prepares a DNS response for sending to the client.
// It handles EDNS0 and truncates if necessary for UDP clients.
func prepareResponse(resp *dns.Msg, req *dns.Msg, clientUsedTCP bool) *dns.Msg {
	// Build a clean response to avoid Copy() issues with OPT records
	cleanResp := buildCleanResponse(resp, req)

	// Add EDNS0 if client requested it
	setEdns0(cleanResp, req)

	// Truncate for UDP clients if response exceeds their buffer size
	if !clientUsedTCP {
		clientMaxSize := uint16(512)
		if o := req.IsEdns0(); o != nil {
			clientMaxSize = o.UDPSize()
		}
		if clientMaxSize > ednsBufferSize {
			clientMaxSize = ednsBufferSize
		}
		if cleanResp.Len() > int(clientMaxSize) {
			cleanResp.Truncated = true
			cleanResp.Answer = nil
			cleanResp.Ns = nil
			cleanResp.Extra = nil
			setEdns0(cleanResp, req)
		}
	}

	return cleanResp
}

// buildErrorResponse creates an error response with proper flags.
func buildErrorResponse(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.Id = req.Id
	m.Response = true
	m.Opcode = req.Opcode
	m.RecursionDesired = req.RecursionDesired
	m.RecursionAvailable = true
	m.AuthenticatedData = false
	m.CheckingDisabled = req.CheckingDisabled
	m.Rcode = rcode
	m.Question = req.Question
	setEdns0(m, req)
	return m
}

// ServeDNS implements the dns.Handler interface.
//
// Note: No query rate limiting is implemented. The DNS server runs in an isolated
// VM network where only the VM's resolved can reach it, so amplification attacks
// are not a concern.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		sendResponse(w, buildErrorResponse(r, dns.RcodeFormatError))
		return
	}

	q := r.Question[0]
	atomic.AddUint64(&s.stats.TotalQueries, 1)

	// Handle healthcheck domain - always responds regardless of mode or allowlist
	if s.handleHealthcheck(w, r, q) {
		return
	}

	source := ""
	if addr := w.RemoteAddr(); addr != nil {
		source = addr.String()
	}

	// Log domain if in passive mode (captures to profile)
	if !s.IsActive() {
		s.LogDomain("DNS", q.Name)
		logging.Debug("dns query forwarded (passive mode)",
			"domain", q.Name,
			"type", dns.TypeToString[q.Qtype],
			"source", source,
		)
	}

	// Track explicit allowlist match separately from passive-mode "allow everything".
	// Explicitly allowlisted domains skip rebinding protection (the user trusts them).
	explicitlyAllowed := s.filter.IsAllowed(q.Name)
	allowed := explicitlyAllowed || !s.IsActive()

	if !allowed {
		atomic.AddUint64(&s.stats.BlockedQueries, 1)
		sendResponse(w, buildErrorResponse(r, dns.RcodeNameError), "domain", q.Name)

		// Log block to traffic log
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogBlock(q.Name, "not_in_allowlist", source,
				logging.WithType(dns.TypeToString[q.Qtype]))
		}
		return
	}

	atomic.AddUint64(&s.stats.AllowedQueries, 1)

	clientUsedTCP := false
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		clientUsedTCP = true
	}

	// Query upstream
	resp, err := getResolver().Exchange(r, s.upstream)
	if err != nil {
		sendResponse(w, buildErrorResponse(r, dns.RcodeServerFailure), "domain", q.Name)
		return
	}

	if resp == nil {
		sendResponse(w, buildErrorResponse(r, dns.RcodeServerFailure), "domain", q.Name)
		return
	}

	// SAFETY CHECK: TCP Protocol Violation
	if clientUsedTCP && resp.Truncated {
		sendResponse(w, buildErrorResponse(r, dns.RcodeServerFailure), "domain", q.Name)
		return
	}

	// Log allow to traffic log
	if logger := s.TrafficLogger(); logger != nil {
		logger.LogAllow(q.Name, source,
			logging.WithType(dns.TypeToString[q.Qtype]))
	}

	// Validate DNS response doesn't contain private/blocked IPs (rebinding protection).
	// Skip for explicitly allowlisted domains — if the user trusts the domain,
	// they trust where it resolves.
	if !explicitlyAllowed && s.checkRebinding(w, r, resp, q, source) {
		return
	}

	// Write final response
	sendResponse(w, prepareResponse(resp, r, clientUsedTCP), "domain", q.Name)
}

// sendResponse writes a DNS response and logs on failure.
func sendResponse(w dns.ResponseWriter, msg *dns.Msg, logArgs ...any) {
	if err := w.WriteMsg(msg); err != nil {
		allArgs := append([]any{"error", err}, logArgs...)
		logging.Debug("failed to write DNS response", allArgs...)
	}
}

// handleHealthcheck responds to the healthcheck domain. Returns true if handled.
func (s *Server) handleHealthcheck(w dns.ResponseWriter, r *dns.Msg, q dns.Question) bool {
	if !strings.EqualFold(q.Name, HealthcheckDomain) {
		return false
	}
	atomic.AddUint64(&s.stats.AllowedQueries, 1)
	resp := &dns.Msg{}
	resp.SetReply(r)
	resp.Authoritative = true
	if q.Qtype == dns.TypeA {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("127.0.0.1"),
		})
	}
	sendResponse(w, resp, "domain", q.Name)
	return true
}

// checkRebinding checks for DNS rebinding attacks in the response. Returns true if blocked.
func (s *Server) checkRebinding(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg, q dns.Question, source string) bool {
	for _, rr := range resp.Answer {
		var ip string
		switch record := rr.(type) {
		case *dns.A:
			ip = record.A.String()
		case *dns.AAAA:
			ip = record.AAAA.String()
		default:
			continue
		}
		if filterbase.IsBlockedIP(ip) {
			if logger := s.TrafficLogger(); logger != nil {
				logger.LogBlock(q.Name, "dns_rebinding", source,
					logging.WithType(dns.TypeToString[q.Qtype]))
			}
			sendResponse(w, buildErrorResponse(r, dns.RcodeServerFailure), "domain", q.Name)
			return true
		}
	}
	return false
}

// DNSServer wraps both UDP and TCP dns.Server instances.
type DNSServer struct {
	udp      *dns.Server
	tcp      *dns.Server
	Port     int
	startErr chan error // receives errors from background ActivateAndServe goroutines
}

// StartErr returns a channel that receives errors from the background server
// goroutines. Callers can select on this to detect early startup failures
// (e.g. port bind failures) after Start returns.
func (d *DNSServer) StartErr() <-chan error {
	return d.startErr
}

// Shutdown gracefully stops both UDP and TCP servers.
func (d *DNSServer) Shutdown() error {
	var errs []error
	if d.udp != nil {
		if err := d.udp.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("UDP shutdown: %w", err))
		}
	}
	if d.tcp != nil {
		if err := d.tcp.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("TCP shutdown: %w", err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Start starts the DNS server on both UDP and TCP using the same port.
func (s *Server) Start(addr string) (*DNSServer, error) {
	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP %s: %w", addr, err)
	}

	udpAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = udpConn.Close()
		return nil, errors.New("failed to get UDP address")
	}
	port := udpAddr.Port

	s.SetListenPort(port)

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("invalid address %s: %w", addr, err)
	}
	tcpAddr := fmt.Sprintf("%s:%d", host, port)

	tcpListener, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("failed to listen on TCP %s: %w", tcpAddr, err)
	}

	udpServer := &dns.Server{
		PacketConn: udpConn,
		Handler:    s,
	}
	tcpServer := &dns.Server{
		Listener: tcpListener,
		Handler:  s,
	}

	// Start servers in background, surfacing bind errors via a channel.
	startErr := make(chan error, 2)
	go func() {
		if err := udpServer.ActivateAndServe(); err != nil {
			startErr <- fmt.Errorf("UDP server failed: %w", err)
		}
	}()
	go func() {
		if err := tcpServer.ActivateAndServe(); err != nil {
			startErr <- fmt.Errorf("TCP server failed: %w", err)
		}
	}()

	return &DNSServer{
		udp:      udpServer,
		tcp:      tcpServer,
		Port:     port,
		startErr: startErr,
	}, nil
}
