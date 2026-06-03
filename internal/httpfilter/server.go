// Package httpfilter provides HTTP/HTTPS proxy filtering with domain allowlisting.
package httpfilter

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/cert"
	"github.com/sandialabs/abox/internal/filterbase"
	"github.com/sandialabs/abox/internal/logging"
)

// Stats holds HTTP filter statistics.
type Stats struct {
	TotalRequests   uint64
	AllowedRequests uint64
	BlockedRequests uint64
	StartTime       time.Time
}

// HealthcheckDomain is a sentinel domain that always responds regardless of mode or allowlist.
// This enables reliable troubleshooting and connectivity checks.
const HealthcheckDomain = "healthcheck.abox.local"

// Server handles HTTP proxy requests with filtering.
type Server struct {
	allowlist.ModeController      // embedded mode controller
	filterbase.TrafficLoggerMixin // embedded traffic logger
	filter                        *allowlist.Filter
	stats                         Stats

	// HTTP server + proxy plumbing
	server       *http.Server
	listener     net.Listener
	proxyHandler http.Handler
	transport    *http.Transport
	reverseProxy *httputil.ReverseProxy
	http1Server  *http.Server  // used as BaseConfig for h2 and as the per-conn http.Server template for h1
	http2Server  *http2.Server // h2 server for intercepted MITM connections

	// hijack lifecycle: outer http.Server.Shutdown does not track hijacked
	// connections, so we manage MITM/tunnel session teardown ourselves.
	// activeConns counts each trackedConn-wrapped session and decrements when
	// the wrapper's Close fires (which happens whether the inner server, a
	// ReverseProxy hijack handoff, or the watcher closes it).
	activeConns  sync.WaitGroup
	hijackCtx    context.Context
	hijackCancel context.CancelFunc

	// TLS MITM fields.
	//
	// mitmReady is the publish flag: it is Stored true (last) by LoadCA after
	// caCert/caKey are written, so any goroutine that observes mitmReady==true is
	// guaranteed to see those writes. Invariant: caCert/caKey must only be read on
	// a path already gated by mitmReady.Load()==true (generateCertForHost is
	// reached only via intercept→actionIntercept, which decideConnect returns only
	// after mitmReady is true).
	caCert        *x509.Certificate
	caKey         *ecdsa.PrivateKey
	certCache     sync.Map      // map[string]*certCacheEntry - cached host certificates
	mitmReady     atomic.Bool   // true once MITM CA is configured
	loadOnce      sync.Once     // guards CA publish + cleanup-routine spawn against double LoadCA
	cleanupDone   chan struct{} // closed when background cleanup routine exits
	cleanupCancel func()        // cancels background cleanup
	startErr      chan error    // receives non-fatal startup errors

	// handshakeTimeout bounds the inner TLS handshake on an intercepted MITM
	// connection. A client that completes CONNECT but stalls the ClientHello
	// would otherwise pin a goroutine + conn for the server's lifetime.
	handshakeTimeout time.Duration

	// maxConns caps concurrent client connections (0 = unlimited). Bounds host
	// fd/goroutine use against a hostile VM. Read once in Start.
	maxConns int

	// TLS key logging for packet capture (abox tap)
	keyLog     *keyLogWriter // shared writer set on all MITM TLS configs
	keyLogFile *os.File      // backing file, nil when not logging
}

// certCacheEntry wraps a certificate with metadata for cache management.
type certCacheEntry struct {
	cert       *tls.Certificate
	lastAccess atomic.Int64 // Unix nano timestamp for thread-safe access tracking
}

// maxCertCacheSize limits the certificate cache to prevent unbounded memory growth.
const maxCertCacheSize = 1000

// certCleanupInterval is how often the background routine cleans expired certificates.
const certCleanupInterval = 5 * time.Minute

// keyLogWriter is a thread-safe writer for TLS session keys in NSS Key Log format.
// It is set once on TLS configs and the underlying destination is swapped at runtime
// via StartKeyLog/StopKeyLog. When disabled (w == nil), writes are silently discarded.
type keyLogWriter struct {
	mu sync.Mutex
	w  io.Writer // nil = disabled
}

func (k *keyLogWriter) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.w == nil {
		return len(p), nil // discard when disabled
	}
	return k.w.Write(p)
}

// NewServer creates a new HTTP proxy server.
func NewServer(filter *allowlist.Filter, passive bool) *Server {
	s := &Server{
		filter: filter,
		stats: Stats{
			StartTime: time.Now(),
		},
		keyLog: &keyLogWriter{},
	}
	s.SetActive(!passive)

	s.transport = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", protoHTTP11},
		},
	}
	// http2.ConfigureTransport wires up the h2 round-tripper so upstream h2
	// responses (including trailers) are forwarded by ReverseProxy.
	if err := http2.ConfigureTransport(s.transport); err != nil {
		// Should not fail with our config; treat as programming error.
		logging.Debug("http2.ConfigureTransport failed", "err", err)
	}
	s.reverseProxy = newReverseProxy(s.transport)
	// http1Server is the config template for intercepted MITM h1 connections
	// (proxy.go intercept clones the relevant fields per-call). ReadHeaderTimeout
	// bounds slow-headers attacks; IdleTimeout bounds keepalive lingering. We
	// deliberately omit WriteTimeout here — it would kill long-lived MITM
	// flows (WebSockets, SSE, large downloads).
	s.http1Server = &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	s.http2Server = &http2.Server{}
	s.hijackCtx, s.hijackCancel = context.WithCancel(context.Background())
	// Matches the upstream transport's TLSHandshakeTimeout above.
	s.handshakeTimeout = 10 * time.Second
	// Default connection cap; serve.go overrides from instance config. A
	// concrete default here keeps the cap on even for legacy configs.
	s.maxConns = 512
	s.proxyHandler = newProxyHandler(s)
	return s
}

// extractHost extracts the hostname from a host:port string.
//
// Handles three input shapes:
//   - "example.com:443" or "1.2.3.4:443" — SplitHostPort returns the host.
//   - "[::1]:443" — SplitHostPort returns "::1" without brackets.
//   - "[::1]" or "example.com" or "1.2.3.4" — no port: bracket-strip IPv6
//     literals, return the rest as-is. Without bracket stripping, a bare
//     "[::1]" Host header would pass through to SSRF and allowlist checks
//     with brackets included, silently bypassing both.
func extractHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// trackConn wraps conn so its eventual Close decrements activeConns. Caller
// uses the returned trackedConn (its embedded net.Conn is the original) for
// everything downstream — tls.Server, io.Copy, etc. — so any Close that flows
// through the wrapper deregisters from Shutdown's drain.
func (s *Server) trackConn(conn net.Conn) *trackedConn {
	s.activeConns.Add(1)
	return &trackedConn{
		Conn:    conn,
		onClose: s.activeConns.Done,
		closed:  make(chan struct{}),
	}
}

// urlString returns r.URL.String(), or "" if r or r.URL is nil.
// Defensive even though stdlib h1/h2 servers guarantee non-nil URLs.
func urlString(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.String()
}

// checkHost performs common request checking logic.
// Returns (allowed bool, blockedBySSRF bool).
func (s *Server) checkHost(host string) (allowed, blockedBySSRF bool) {
	// Check if explicitly allowlisted first.
	// Explicitly allowlisted hosts skip SSRF protection — if the user
	// trusts the host, they trust where it points.
	explicitlyAllowed := s.filter.IsAllowed(host)

	// SSRF protection: block requests to private/loopback/link-local IPs
	// Skip for explicitly allowlisted hosts.
	if !explicitlyAllowed && filterbase.IsBlockedIP(host) {
		return false, true
	}

	// Log domain if in passive mode (captures to profile)
	if !s.IsActive() {
		s.LogDomain("HTTP", host)
		logging.Debug("http request forwarded (passive mode)",
			"host", host,
		)
	}

	allowed = explicitlyAllowed || !s.IsActive()
	return allowed, false
}

// decideConnect is the policy callback invoked from proxy.go for every CONNECT
// request. It runs the allowlist + SSRF check on the CONNECT target and
// returns the proxy action.
//
// Stats: blocked-at-CONNECT increments TotalRequests + BlockedRequests here.
// Allowed-with-intercept defers per-request counting to decideRequest.
// Allowed-without-MITM (tunnel) counts as one allow here.
func (s *Server) decideConnect(host string) connectAction {
	allowed, blockedBySSRF := s.checkHost(host)

	if blockedBySSRF {
		atomic.AddUint64(&s.stats.TotalRequests, 1)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		logging.Audit("https blocked private IP",
			"action", logging.ActionHTTPBlockSSRF,
			"host", host,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogBlock(host, "ssrf_private_ip", "")
		}
		return actionReject
	}

	if !allowed {
		atomic.AddUint64(&s.stats.TotalRequests, 1)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		logging.Audit("https blocked",
			"action", logging.ActionHTTPBlock,
			"host", host,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogBlock(host, "not_in_allowlist", "")
		}
		return actionReject
	}

	if !s.mitmReady.Load() {
		// No MITM CA loaded: allow the already-checked CONNECT target through
		// as a transparent tunnel. We cannot inspect inner traffic in this
		// mode, so domain fronting cannot be detected. Enable MITM (LoadCA)
		// for full protection.
		atomic.AddUint64(&s.stats.TotalRequests, 1)
		atomic.AddUint64(&s.stats.AllowedRequests, 1)
		logging.Debug("https allowed without MITM inspection",
			"host", host,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogAllow(host, "")
		}
		return actionTunnel
	}

	return actionIntercept
}

// decideRequest is the policy callback invoked from proxy.go for every
// fully-parsed inbound request (forward proxy and post-MITM, h1 and h2 alike).
// connectTarget is "" for forward-proxy requests and the CONNECT host for
// post-MITM requests.
func (s *Server) decideRequest(r *http.Request, connectTarget string) requestDecision {
	if r == nil {
		return requestDecision{forward: false, status: http.StatusBadRequest, body: "bad request\n"}
	}

	atomic.AddUint64(&s.stats.TotalRequests, 1)

	host := extractHost(r.Host)

	// Healthcheck shortcut: always allow, regardless of mode or allowlist.
	// Skip it for MITM'd requests whose inner Host differs from the CONNECT
	// target, so a spoofed inner Host can't claim healthcheck status (and
	// dodge the cross-origin audit) while tunneled to a different target.
	if strings.EqualFold(host, HealthcheckDomain) &&
		(connectTarget == "" || strings.EqualFold(extractHost(connectTarget), host)) {
		atomic.AddUint64(&s.stats.AllowedRequests, 1)
		return requestDecision{
			forward: false,
			status:  http.StatusOK,
			body:    "abox healthcheck OK\n",
		}
	}

	allowed, blockedBySSRF := s.checkHost(host)

	if blockedBySSRF {
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		logging.Audit("http blocked private IP",
			"action", logging.ActionHTTPBlockSSRF,
			"host", host,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogBlock(host, "ssrf_private_ip", "",
				logging.WithMethod(r.Method), logging.WithURL(urlString(r)))
		}
		return requestDecision{forward: false, status: http.StatusForbidden, body: "Access denied\n"}
	}

	if !allowed {
		atomic.AddUint64(&s.stats.BlockedRequests, 1)

		// Domain fronting: HTTPS inner Host differs from CONNECT target.
		// Only meaningful for MITM'd requests (connectTarget != "").
		// connectTarget is "host:port"; compare bare hosts.
		if connectTarget != "" && !strings.EqualFold(extractHost(connectTarget), host) {
			logging.Audit("https blocked domain fronting",
				"action", logging.ActionHTTPBlockFronting,
				"connect_host", connectTarget,
				"host_header", host,
				"url", urlString(r),
			)
			if logger := s.TrafficLogger(); logger != nil {
				logger.LogBlock(host, "domain_fronting", "",
					logging.WithMethod(r.Method), logging.WithURL(urlString(r)))
			}
		} else {
			logging.Audit("http blocked",
				"action", logging.ActionHTTPBlock,
				"host", host,
			)
			if logger := s.TrafficLogger(); logger != nil {
				logger.LogBlock(host, "not_in_allowlist", "",
					logging.WithMethod(r.Method), logging.WithURL(urlString(r)))
			}
		}
		return requestDecision{forward: false, status: http.StatusForbidden, body: "Access denied\n"}
	}

	atomic.AddUint64(&s.stats.AllowedRequests, 1)

	// Cross-origin allow: MITM'd request whose inner Host differs from the
	// CONNECT target, but both are allowlisted. Not a block (no unallowed
	// traffic), yet the request is delivered to the pinned CONNECT target while
	// claiming a different Host — audit it so the mismatch is visible.
	allowOpts := []logging.EventOption{logging.WithMethod(r.Method), logging.WithURL(urlString(r))}
	if connectTarget != "" && !strings.EqualFold(extractHost(connectTarget), host) {
		logging.Audit("https allowed cross-origin host",
			"action", logging.ActionHTTPAllowFronting,
			"connect_host", connectTarget,
			"host_header", host,
			"url", urlString(r),
		)
		allowOpts = append(allowOpts, logging.WithReason("cross_origin_allowed"))
	}

	if logger := s.TrafficLogger(); logger != nil {
		logger.LogAllow(host, "", allowOpts...)
	}
	return requestDecision{forward: true}
}

// SetMaxConns sets the concurrent client-connection cap. n <= 0 means
// unlimited. Must be called before Start (read once there).
func (s *Server) SetMaxConns(n int) {
	if n < 0 {
		n = 0
	}
	s.maxConns = n
}

// Start starts the HTTP proxy server.
func (s *Server) Start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener

	// Get actual port if port 0 was specified
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return errors.New("failed to get TCP address")
	}

	s.SetListenPort(tcpAddr.Port)

	// Cap concurrent connections to bound host fd/goroutine use against a
	// hostile VM. LimitListener queues excess Accepts; it covers hijacked
	// MITM/tunnel conns too because the limit-wrapped conn's Close (reached via
	// trackedConn) releases the semaphore. s.listener stays the raw listener so
	// Shutdown/Addr operate on it.
	served := listener
	if s.maxConns > 0 {
		served = newLimitedListener(listener, s.maxConns)
	}

	s.server = &http.Server{
		Handler:      s.proxyHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.startErr = make(chan error, 1)
	go func() {
		if err := s.server.Serve(served); err != nil && err != http.ErrServerClosed {
			s.startErr <- err
		}
	}()

	return nil
}

// StartErr returns a channel that receives startup errors.
func (s *Server) StartErr() <-chan error {
	return s.startErr
}

// Shutdown gracefully shuts down the server.
//
// Order:
//  1. Start the outer http.Server.Shutdown in a goroutine. It sets the
//     server's shuttingDown flag synchronously, so by the time any subsequent
//     work begins, the listener has stopped accepting new requests — this
//     closes the (otherwise theoretical) window in which a fresh CONNECT
//     would call activeConns.Add(1) concurrent with our Wait.
//  2. Cancel the hijack context: watchers close their tracked conns, which
//     cascades through the inner h2/h1 servers and any ReverseProxy hijack
//     handoff, letting each trackedConn's Done fire.
//  3. Drain the cert cleanup routine and the upstream connection pool.
//  4. Wait for activeConns to drain (bounded by ctx).
//  5. Wait for the outer server.Shutdown goroutine to return (also bounded).
func (s *Server) Shutdown(ctx context.Context) error {
	s.StopKeyLog()

	if ctx == nil {
		ctx = context.Background()
	}

	serverDone := make(chan error, 1)
	go func() {
		if s.server != nil {
			serverDone <- s.server.Shutdown(ctx)
		} else {
			serverDone <- nil
		}
	}()

	if s.hijackCancel != nil {
		s.hijackCancel()
	}

	// Gate on mitmReady so the cleanupCancel/cleanupDone reads carry the same
	// publish guarantee as caCert/caKey: both are written before mitmReady.Store
	// inside loadOnce, so observing mitmReady==true makes them visible without a
	// separate lock. When MITM is disabled the Once never ran and both are nil.
	if s.mitmReady.Load() && s.cleanupCancel != nil {
		s.cleanupCancel()
		select {
		case <-s.cleanupDone:
		case <-ctx.Done():
		}
	}

	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}

	connsDone := make(chan struct{})
	go func() {
		s.activeConns.Wait()
		close(connsDone)
	}()
	select {
	case <-connsDone:
	case <-ctx.Done():
	}

	select {
	case err := <-serverDone:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// StartKeyLog begins writing TLS session keys to the given file path.
// Keys are written in NSS Key Log format for use with Wireshark/Suricata.
func (s *Server) StartKeyLog(path string) error {
	s.stopKeyLogLocked() // close any existing keylog

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open keylog file: %w", err)
	}

	s.keyLog.mu.Lock()
	s.keyLogFile = f
	s.keyLog.w = f
	s.keyLog.mu.Unlock()

	logging.Debug("TLS key logging started", "path", path)
	return nil
}

// StopKeyLog stops writing TLS session keys and closes the backing file.
func (s *Server) StopKeyLog() {
	s.stopKeyLogLocked()
}

func (s *Server) stopKeyLogLocked() {
	s.keyLog.mu.Lock()
	s.keyLog.w = nil
	f := s.keyLogFile
	s.keyLogFile = nil
	s.keyLog.mu.Unlock()

	if f != nil {
		f.Close()
		logging.Debug("TLS key logging stopped")
	}
}

// GetStats returns current statistics.
func (s *Server) GetStats() Stats {
	return Stats{
		TotalRequests:   atomic.LoadUint64(&s.stats.TotalRequests),
		AllowedRequests: atomic.LoadUint64(&s.stats.AllowedRequests),
		BlockedRequests: atomic.LoadUint64(&s.stats.BlockedRequests),
		StartTime:       s.stats.StartTime,
	}
}

// InitTrafficLogger initializes the traffic logger for this server.
func (s *Server) InitTrafficLogger(logPath string) error {
	return s.TrafficLoggerMixin.InitTrafficLogger(logPath, schemeHTTP)
}

// LoadCA loads a CA certificate and key for TLS MITM.
// Once loaded, HTTPS connections will be intercepted and decrypted.
// This also starts a background routine to clean expired certificates.
//
// A failed load (bad/missing files) returns an error and may be retried. The
// first successful load is the one that takes effect: a later successful LoadCA
// is a no-op for the active CA (the cleanup routine is spawned only once).
func (s *Server) LoadCA(certPath, keyPath string) error {
	caCert, caKey, err := cert.LoadCA(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// cert.LoadCA stays outside loadOnce so the call remains retryable and its
	// error is returned normally. loadOnce guards only the publish + cleanup-
	// routine spawn, so a second LoadCA cannot orphan the first certCleanupRoutine.
	// A second successful LoadCA is therefore a no-op for the active CA.
	s.loadOnce.Do(func() {
		s.caCert = caCert
		s.caKey = caKey

		// Start background certificate cleanup routine
		ctx, cancel := context.WithCancel(context.Background())
		s.cleanupCancel = cancel
		s.cleanupDone = make(chan struct{})
		go s.certCleanupRoutine(ctx)

		s.mitmReady.Store(true) // publish LAST: see the mitmReady invariant above
	})

	logging.Debug("MITM CA loaded", "cert", certPath)
	return nil
}

// IsMITMEnabled returns true if TLS MITM is configured.
func (s *Server) IsMITMEnabled() bool {
	return s.mitmReady.Load()
}

// generateCertForHost returns a TLS config with a certificate for the given host.
// Certificates are cached to avoid regenerating for each request. The proxy
// intercept path clones the returned config before mutating NextProtos.
func (s *Server) generateCertForHost(host string) (*tls.Config, error) {
	now := time.Now()
	nowNano := now.UnixNano()

	// Check cache first
	if cached, ok := s.certCache.Load(host); ok {
		entry, ok := cached.(*certCacheEntry)
		switch {
		case !ok:
			s.certCache.Delete(host)
		case entry.cert.Leaf != nil && entry.cert.Leaf.NotAfter.After(now):
			// Update last access time atomically for LRU tracking
			entry.lastAccess.Store(nowNano)
			return &tls.Config{
				Certificates: []tls.Certificate{*entry.cert},
				MinVersion:   tls.VersionTLS12,      // Enforce TLS 1.2+ to prevent downgrade attacks
				NextProtos:   []string{protoHTTP11}, // Overridden to ["h2", "http/1.1"] by the proxy intercept path
				KeyLogWriter: s.keyLog,              // TLS session key export for abox tap
			}, nil
		default:
			// Certificate expired, remove from cache
			s.certCache.Delete(host)
		}
	}

	// Generate new certificate signed by our CA
	hostCert, err := cert.SignHostCert(host, s.caCert, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate for %s: %w", host, err)
	}

	// Enforce cache size limit before adding new entry
	s.evictOldestIfNeeded()

	// Cache and return
	entry := &certCacheEntry{
		cert: hostCert,
	}
	entry.lastAccess.Store(nowNano)
	s.certCache.Store(host, entry)

	return &tls.Config{
		Certificates: []tls.Certificate{*hostCert},
		MinVersion:   tls.VersionTLS12,      // Enforce TLS 1.2+ to prevent downgrade attacks
		NextProtos:   []string{protoHTTP11}, // Overridden to ["h2", "http/1.1"] by the proxy intercept path
		KeyLogWriter: s.keyLog,              // TLS session key export for abox tap
	}, nil
}

// evictOldestIfNeeded removes the oldest 10% of cache entries when the cache exceeds
// maxCertCacheSize. Batch eviction amortizes the O(n) scan cost across multiple entries.
func (s *Server) evictOldestIfNeeded() {
	var (
		count   int
		entries []struct {
			key        any
			accessTime int64
		}
	)

	s.certCache.Range(func(key, value any) bool {
		count++
		entry, ok := value.(*certCacheEntry)
		if !ok {
			s.certCache.Delete(key)
			return true
		}
		entries = append(entries, struct {
			key        any
			accessTime int64
		}{key, entry.lastAccess.Load()})
		return true
	})

	if count < maxCertCacheSize {
		return
	}

	// Evict oldest 10% to amortize the O(n) scan
	evictCount := max(count/10, 1)

	// Sort by access time ascending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].accessTime < entries[j].accessTime
	})

	for i := 0; i < evictCount && i < len(entries); i++ {
		s.certCache.Delete(entries[i].key)
	}
}

// certCleanupRoutine periodically removes expired certificates from the cache.
func (s *Server) certCleanupRoutine(ctx context.Context) {
	defer close(s.cleanupDone)

	ticker := time.NewTicker(certCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanExpiredCerts()
		}
	}
}

// cleanExpiredCerts removes all expired certificates from the cache.
func (s *Server) cleanExpiredCerts() {
	now := time.Now()
	var expiredKeys []string

	s.certCache.Range(func(key, value any) bool {
		entry, ok := value.(*certCacheEntry)
		if !ok {
			s.certCache.Delete(key)
			return true
		}
		if entry.cert.Leaf != nil && entry.cert.Leaf.NotAfter.Before(now) {
			if k, ok := key.(string); ok {
				expiredKeys = append(expiredKeys, k)
			}
		}
		return true
	})

	for _, key := range expiredKeys {
		s.certCache.Delete(key)
	}

	if len(expiredKeys) > 0 {
		logging.Debug("cleaned expired certificates from cache", "count", len(expiredKeys))
	}
}
