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
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

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
	proxy                         *goproxy.ProxyHttpServer
	server                        *http.Server
	listener                      net.Listener

	// TLS MITM fields
	caCert        *x509.Certificate
	caKey         *ecdsa.PrivateKey
	certCache     sync.Map      // map[string]*certCacheEntry - cached host certificates
	mitmReady     bool          // true if MITM is configured
	cleanupDone   chan struct{} // closed when background cleanup routine exits
	cleanupCancel func()        // cancels background cleanup
	startErr      chan error    // receives non-fatal startup errors

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

	// Create goproxy instance
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Handle HTTP requests - check Host header
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return s.handleRequest(r, ctx)
	})

	// Handle HTTPS CONNECT - check hostname
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return s.handleConnect(host, ctx)
	})

	s.proxy = proxy
	return s
}

// extractHost extracts the hostname from a host:port string.
func extractHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
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

// handleRequest handles HTTP (non-CONNECT) requests.
// With MITM enabled, this also handles decrypted HTTPS requests and can detect
// domain fronting attacks by checking the Host header against the allowlist.
func (s *Server) handleRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	atomic.AddUint64(&s.stats.TotalRequests, 1)

	host := extractHost(r.Host)

	// Handle healthcheck domain - always responds regardless of mode or allowlist
	if strings.EqualFold(host, HealthcheckDomain) {
		atomic.AddUint64(&s.stats.AllowedRequests, 1)
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusOK,
			"abox healthcheck OK\n")
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
				logging.WithMethod(r.Method), logging.WithURL(r.URL.String()))
		}
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
			"Access denied\n")
	}

	if !allowed {
		atomic.AddUint64(&s.stats.BlockedRequests, 1)

		if resp := s.checkDomainFronting(r, ctx, host); resp != nil {
			return r, resp
		}

		logging.Audit("http blocked",
			"action", logging.ActionHTTPBlock,
			"host", host,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogBlock(host, "not_in_allowlist", "",
				logging.WithMethod(r.Method), logging.WithURL(r.URL.String()))
		}
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
			"Access denied\n")
	}

	atomic.AddUint64(&s.stats.AllowedRequests, 1)
	// Log allowed request
	if logger := s.TrafficLogger(); logger != nil {
		logger.LogAllow(host, "",
			logging.WithMethod(r.Method), logging.WithURL(r.URL.String()))
	}
	return r, nil
}

// checkDomainFronting detects domain fronting (HTTPS Host header differs from CONNECT target).
// Returns a forbidden response if fronting is detected, nil otherwise.
func (s *Server) checkDomainFronting(r *http.Request, ctx *goproxy.ProxyCtx, host string) *http.Response {
	if r.TLS == nil || ctx == nil || ctx.Req == nil {
		return nil
	}
	connectHost := extractHost(ctx.Req.Host)
	if connectHost == "" || strings.EqualFold(connectHost, host) {
		return nil
	}
	logging.Audit("https blocked domain fronting",
		"action", logging.ActionHTTPBlockFronting,
		"connect_host", connectHost,
		"host_header", host,
		"url", r.URL.String(),
	)
	if logger := s.TrafficLogger(); logger != nil {
		logger.LogBlock(host, "domain_fronting", "",
			logging.WithMethod(r.Method), logging.WithURL(r.URL.String()))
	}
	return goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Access denied\n")
}

// handleConnect handles HTTPS CONNECT requests.
func (s *Server) handleConnect(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	// Note: We don't increment stats here for MITM mode because the actual
	// request will be counted in handleRequest after decryption.
	// For non-MITM mode, we count here as before.

	hostname := extractHost(host)
	allowed, blockedBySSRF := s.checkHost(hostname)

	if blockedBySSRF {
		atomic.AddUint64(&s.stats.TotalRequests, 1)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		logging.Audit("https blocked private IP",
			"action", logging.ActionHTTPBlockSSRF,
			"host", hostname,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogBlock(hostname, "ssrf_private_ip", "")
		}
		return goproxy.RejectConnect, host
	}

	if !allowed {
		atomic.AddUint64(&s.stats.TotalRequests, 1)
		atomic.AddUint64(&s.stats.BlockedRequests, 1)
		logging.Audit("https blocked",
			"action", logging.ActionHTTPBlock,
			"host", hostname,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogBlock(hostname, "not_in_allowlist", "")
		}
		return goproxy.RejectConnect, host
	}

	// If MITM is not configured, allow the already-checked CONNECT target through.
	// Note: Without MITM we cannot inspect the inner HTTP Host header, so domain
	// fronting attacks (connecting to allowed-host but sending requests to a
	// different Host) are not detected. Enable MITM (LoadCA) for full protection.
	if !s.mitmReady {
		atomic.AddUint64(&s.stats.TotalRequests, 1)
		atomic.AddUint64(&s.stats.AllowedRequests, 1)
		logging.Debug("https allowed without MITM inspection",
			"host", hostname,
		)
		if logger := s.TrafficLogger(); logger != nil {
			logger.LogAllow(hostname, "")
		}
		return goproxy.OkConnect, host
	}

	// Intercept the connection to validate Host header after decryption
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm,
		TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
			return s.generateCertForHost(extractHost(host), ctx)
		},
	}, host
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

	s.server = &http.Server{
		Handler:      s.proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.startErr = make(chan error, 1)
	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
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
func (s *Server) Shutdown(ctx context.Context) error {
	// Stop any active TLS key logging
	s.StopKeyLog()

	// Stop the certificate cleanup routine
	if s.cleanupCancel != nil {
		s.cleanupCancel()
		// Wait for cleanup routine to finish (with timeout from context)
		if s.cleanupDone != nil {
			if ctx != nil {
				select {
				case <-s.cleanupDone:
				case <-ctx.Done():
				}
			} else {
				<-s.cleanupDone
			}
		}
	}

	if s.server != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		return s.server.Shutdown(ctx)
	}
	return nil
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
	return s.TrafficLoggerMixin.InitTrafficLogger(logPath, "http")
}

// LoadCA loads a CA certificate and key for TLS MITM.
// Once loaded, HTTPS connections will be intercepted and decrypted.
// This also starts a background routine to clean expired certificates.
func (s *Server) LoadCA(certPath, keyPath string) error {
	caCert, caKey, err := cert.LoadCA(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	s.caCert = caCert
	s.caKey = caKey
	s.mitmReady = true

	// Start background certificate cleanup routine
	ctx, cancel := context.WithCancel(context.Background())
	s.cleanupCancel = cancel
	s.cleanupDone = make(chan struct{})
	go s.certCleanupRoutine(ctx)

	logging.Debug("MITM CA loaded", "cert", certPath)
	return nil
}

// IsMITMEnabled returns true if TLS MITM is configured.
func (s *Server) IsMITMEnabled() bool {
	return s.mitmReady
}

// generateCertForHost returns a TLS config with a certificate for the given host.
// Certificates are cached to avoid regenerating for each request.
func (s *Server) generateCertForHost(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
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
				MinVersion:   tls.VersionTLS12, // Enforce TLS 1.2+ to prevent downgrade attacks
				KeyLogWriter: s.keyLog,         // TLS session key export for abox tap
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
		MinVersion:   tls.VersionTLS12, // Enforce TLS 1.2+ to prevent downgrade attacks
		KeyLogWriter: s.keyLog,         // TLS session key export for abox tap
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
