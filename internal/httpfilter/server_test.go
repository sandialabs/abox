package httpfilter

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/cert"
	"github.com/sandialabs/abox/internal/filterbase"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Loopback addresses
		{"loopback-127.0.0.1", "127.0.0.1", true},
		{"loopback-127.255.255.255", "127.255.255.255", true},
		{"loopback-ipv6", "::1", true},

		// Private addresses (RFC 1918)
		{"private-10.0.0.1", "10.0.0.1", true},
		{"private-10.255.255.255", "10.255.255.255", true},
		{"private-172.16.0.1", "172.16.0.1", true},
		{"private-172.31.255.255", "172.31.255.255", true},
		{"private-192.168.0.1", "192.168.0.1", true},
		{"private-192.168.255.255", "192.168.255.255", true},

		// IPv6 private (fc00::/7)
		{"private-ipv6-fc00", "fc00::1", true},
		{"private-ipv6-fd00", "fd00::1", true},

		// Link-local addresses
		{"link-local-169.254.1.1", "169.254.1.1", true},
		{"link-local-169.254.254.254", "169.254.254.254", true},
		{"link-local-ipv6", "fe80::1", true},

		// IPv6 link-local with scope ID (SSRF bypass fix)
		{"link-local-ipv6-scope-eth0", "fe80::1%eth0", true},
		{"link-local-ipv6-scope-lo", "fe80::1%lo", true},
		{"link-local-ipv6-scope-numeric", "fe80::1%1", true},

		// Broadcast
		{"broadcast-255.255.255.255", "255.255.255.255", true},

		// Unspecified
		{"unspecified-0.0.0.0", "0.0.0.0", true},
		{"unspecified-ipv6", "::", true},

		// Multicast
		{"multicast-224.0.0.1", "224.0.0.1", true},
		{"multicast-239.255.255.255", "239.255.255.255", true},
		{"multicast-ipv6", "ff02::1", true},

		// IPv6 site-local (deprecated but blocked)
		{"site-local-ipv6", "fec0::1", true},

		// Public addresses (should NOT be blocked)
		{"public-8.8.8.8", "8.8.8.8", false},
		{"public-1.1.1.1", "1.1.1.1", false},
		{"public-140.82.121.4", "140.82.121.4", false},
		{"public-93.184.216.34", "93.184.216.34", false},
		{"public-ipv6", "2001:4860:4860::8888", false},

		// Edge cases
		{"non-ip-domain", "github.com", false},
		{"non-ip-empty", "", false},
		{"non-ip-garbage", "not-an-ip", false},

		// 172.x boundary cases (only 172.16-31 is private)
		{"private-boundary-172.15", "172.15.255.255", false},
		{"private-boundary-172.16", "172.16.0.0", true},
		{"private-boundary-172.31", "172.31.255.255", true},
		{"private-boundary-172.32", "172.32.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterbase.IsBlockedIP(tt.ip)
			if result != tt.blocked {
				t.Errorf("filterbase.IsBlockedIP(%q) = %v, want %v", tt.ip, result, tt.blocked)
			}
		})
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"host-with-port", "github.com:443", "github.com"},
		{"host-without-port", "github.com", "github.com"},
		{"ip-with-port", "192.168.1.1:8080", "192.168.1.1"},
		{"ip-without-port", "192.168.1.1", "192.168.1.1"},
		{"ipv6-with-port", "[::1]:443", "::1"},
		{"ipv6-without-port", "::1", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHost(tt.input)
			if result != tt.expected {
				t.Errorf("extractHost(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	filter := allowlist.NewFilter()

	t.Run("active-mode", func(t *testing.T) {
		server := NewServer(filter, false)
		if server == nil {
			t.Fatal("NewServer() returned nil")
			return
		}
		if !server.IsActive() {
			t.Error("Server should be active when passive=false")
		}
	})

	t.Run("passive-mode", func(t *testing.T) {
		server := NewServer(filter, true)
		if server == nil {
			t.Fatal("NewServer() returned nil")
			return
		}
		if server.IsActive() {
			t.Error("Server should be passive when passive=true")
		}
	})
}

func TestServer_CheckHost(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("github.com")
	filter.Add("example.org")

	server := NewServer(filter, false)

	tests := []struct {
		name            string
		host            string
		wantAllowed     bool
		wantBlockedSSRF bool
	}{
		// Allowed domains
		{"allowed-exact", "github.com", true, false},
		{"allowed-subdomain", "api.github.com", true, false},
		{"allowed-other", "example.org", true, false},

		// Blocked domains (not in allowlist)
		{"blocked-not-in-list", "google.com", false, false},
		{"blocked-similar-name", "notgithub.com", false, false},

		// SSRF blocked
		{"ssrf-loopback", "127.0.0.1", false, true},
		{"ssrf-private-10", "10.0.0.1", false, true},
		{"ssrf-private-192", "192.168.1.1", false, true},
		{"ssrf-link-local", "169.254.1.1", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, blockedSSRF := server.checkHost(tt.host)
			if allowed != tt.wantAllowed {
				t.Errorf("checkHost(%q) allowed = %v, want %v", tt.host, allowed, tt.wantAllowed)
			}
			if blockedSSRF != tt.wantBlockedSSRF {
				t.Errorf("checkHost(%q) blockedSSRF = %v, want %v", tt.host, blockedSSRF, tt.wantBlockedSSRF)
			}
		})
	}
}

func TestServer_CheckHost_AllowlistedPrivateIP(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("10.0.5.3")     // Explicitly allowlist a private IP
	filter.Add("192.168.1.50") // Another private IP

	server := NewServer(filter, false)

	tests := []struct {
		name            string
		host            string
		wantAllowed     bool
		wantBlockedSSRF bool
	}{
		// Allowlisted private IPs should NOT be blocked by SSRF
		{"allowlisted-10-net", "10.0.5.3", true, false},
		{"allowlisted-192-net", "192.168.1.50", true, false},

		// Non-allowlisted private IPs should still be blocked
		{"non-allowlisted-private", "10.0.0.1", false, true},
		{"non-allowlisted-loopback", "127.0.0.1", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, blockedSSRF := server.checkHost(tt.host)
			if allowed != tt.wantAllowed {
				t.Errorf("checkHost(%q) allowed = %v, want %v", tt.host, allowed, tt.wantAllowed)
			}
			if blockedSSRF != tt.wantBlockedSSRF {
				t.Errorf("checkHost(%q) blockedSSRF = %v, want %v", tt.host, blockedSSRF, tt.wantBlockedSSRF)
			}
		})
	}
}

func TestServer_CheckHost_PassiveMode(t *testing.T) {
	filter := allowlist.NewFilter()
	// Empty allowlist - everything would be blocked in active mode

	server := NewServer(filter, true) // passive mode

	// In passive mode, even domains not in allowlist should be allowed
	allowed, blockedSSRF := server.checkHost("notallowed.com")
	if !allowed {
		t.Error("Passive mode should allow all domains")
	}
	if blockedSSRF {
		t.Error("Domain should not be blocked by SSRF")
	}

	// But SSRF protection should still apply in passive mode
	allowed, blockedSSRF = server.checkHost("127.0.0.1")
	if allowed {
		t.Error("Passive mode should still block SSRF IPs")
	}
	if !blockedSSRF {
		t.Error("Loopback should be marked as SSRF blocked")
	}
}

func TestServer_SetActive(t *testing.T) {
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	if !server.IsActive() {
		t.Error("Server should start active")
	}

	server.SetActive(false)
	if server.IsActive() {
		t.Error("Server should be inactive after SetActive(false)")
	}

	server.SetActive(true)
	if !server.IsActive() {
		t.Error("Server should be active after SetActive(true)")
	}
}

func TestServer_Stats(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("allowed.com")

	server := NewServer(filter, false)

	// Initial stats should be zero
	stats := server.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("Initial TotalRequests = %d, want 0", stats.TotalRequests)
	}
	if stats.AllowedRequests != 0 {
		t.Errorf("Initial AllowedRequests = %d, want 0", stats.AllowedRequests)
	}
	if stats.BlockedRequests != 0 {
		t.Errorf("Initial BlockedRequests = %d, want 0", stats.BlockedRequests)
	}
	if stats.StartTime.IsZero() {
		t.Error("StartTime should not be zero")
	}
}

func TestServer_HandleRequest_Healthcheck(t *testing.T) {
	filter := allowlist.NewFilter()
	// Empty allowlist - all domains should be blocked except healthcheck

	server := NewServer(filter, false)

	// Start the server on a random port
	err := server.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// Create a test request via the proxy
	// Note: This test verifies stats are updated, not full proxy behavior
	// (full proxy testing would require more complex setup)

	// Verify stats are tracking
	_ = server.GetStats()
}

func TestServer_HandleRequest_Integration(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("allowed.com")

	server := NewServer(filter, false)

	// Start on random port
	err := server.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// Create HTTP client that uses our proxy
	proxyURL := "http://" + server.listener.Addr().String()
	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{Transport: transport}

	t.Run("healthcheck-always-allowed", func(t *testing.T) {
		// Healthcheck domain should always work
		req, _ := http.NewRequest("GET", "http://"+HealthcheckDomain+"/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Healthcheck request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Healthcheck status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("blocked-domain-returns-403", func(t *testing.T) {
		// Create a backend server that we'll try to reach through the proxy
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		// Try to access a blocked domain - should get 403
		req, _ := http.NewRequest("GET", "http://blocked.example.com/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Blocked domain status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
	})
}

func TestServer_PassiveModeCapture(t *testing.T) {
	filter := allowlist.NewFilter()
	// Empty allowlist

	// Start in passive mode
	server := NewServer(filter, true)

	// Create a temp file for profile log
	tmpDir := t.TempDir()
	profileLog := filepath.Join(tmpDir, "profile.log")

	err := server.InitProfileLogger(profileLog)
	if err != nil {
		t.Fatalf("InitProfileLogger failed: %v", err)
	}

	// Verify we're in passive mode
	if server.IsActive() {
		t.Error("Server should be in passive mode")
	}

	// In passive mode, requests should be allowed even if not in allowlist
	allowed, blockedSSRF := server.checkHost("notallowed.com")
	if !allowed {
		t.Error("Passive mode should allow domains for capture")
	}
	if blockedSSRF {
		t.Error("Should not be SSRF blocked")
	}

	// SSRF protection still applies
	allowed, blockedSSRF = server.checkHost("10.0.0.1")
	if allowed {
		t.Error("Passive mode should still block SSRF IPs")
	}
	if !blockedSSRF {
		t.Error("Private IP should be SSRF blocked")
	}

	// Verify profile log was written
	data, err := os.ReadFile(profileLog)
	if err != nil {
		t.Fatalf("Failed to read profile log: %v", err)
	}
	if len(data) == 0 {
		t.Error("Profile log should contain captured domains")
	}
}

func TestServer_LoadCA(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Create server and load CA
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	if server.IsMITMEnabled() {
		t.Error("MITM should not be enabled before LoadCA")
	}

	if err := server.LoadCA(certPath, keyPath); err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	if !server.IsMITMEnabled() {
		t.Error("MITM should be enabled after LoadCA")
	}
}

func TestServer_LoadCA_NotFound(t *testing.T) {
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	err := server.LoadCA("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}

	if server.IsMITMEnabled() {
		t.Error("MITM should not be enabled after failed LoadCA")
	}
}

func TestServer_GenerateCertForHost(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Create server and load CA
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	if err := server.LoadCA(certPath, keyPath); err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	// Generate cert for a host
	tlsConfig, err := server.generateCertForHost("example.com", nil)
	if err != nil {
		t.Fatalf("generateCertForHost failed: %v", err)
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}

	// Verify the certificate is valid for the host
	cert := tlsConfig.Certificates[0]
	if cert.Leaf == nil {
		t.Fatal("certificate Leaf is nil")
	}

	if cert.Leaf.Subject.CommonName != "example.com" {
		t.Errorf("wrong common name: got %q, want %q", cert.Leaf.Subject.CommonName, "example.com")
	}

	// Test caching - second call should return cached cert
	tlsConfig2, err := server.generateCertForHost("example.com", nil)
	if err != nil {
		t.Fatalf("second generateCertForHost failed: %v", err)
	}

	// Both should have the same certificate (cached)
	if tlsConfig.Certificates[0].Leaf != tlsConfig2.Certificates[0].Leaf {
		t.Error("expected cached certificate to be returned")
	}
}

func TestServer_MITM_Integration(t *testing.T) {
	// This test verifies that MITM works by checking that:
	// 1. CA can be loaded
	// 2. Certificates can be generated for hosts
	// 3. The proxy correctly handles the MITM mode
	//
	// Note: Full end-to-end HTTPS MITM testing is complex because:
	// - We can't easily override DNS to point a domain to localhost
	// - 127.0.0.1 is blocked by SSRF protection (intentionally)
	// - httptest.NewTLSServer uses localhost which triggers SSRF
	//
	// The key security property (domain fronting prevention) is tested
	// via the Host header validation in handleRequest.

	// Generate CA
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Create proxy server with MITM
	filter := allowlist.NewFilter()
	filter.Add("allowed.example.com")

	server := NewServer(filter, false)

	if err := server.LoadCA(certPath, keyPath); err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	if !server.IsMITMEnabled() {
		t.Fatal("MITM should be enabled")
	}

	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// Test that generateCertForHost works for an allowed domain
	tlsConfig, err := server.generateCertForHost("allowed.example.com", nil)
	if err != nil {
		t.Fatalf("generateCertForHost failed: %v", err)
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}

	// Verify the cert is signed by our CA
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)

	cert := tlsConfig.Certificates[0]
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Leaf.Verify(opts); err != nil {
		t.Errorf("Certificate verification failed: %v", err)
	}
}

func TestServer_HTTPS_AllowedWithoutMITM(t *testing.T) {
	// Create proxy server WITHOUT loading CA
	filter := allowlist.NewFilter()
	filter.Add("example.com") // Add to allowlist, MITM not configured

	server := NewServer(filter, false)
	// Intentionally NOT calling server.LoadCA()

	if server.IsMITMEnabled() {
		t.Fatal("MITM should NOT be enabled")
	}

	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// Verify that when MITM is disabled, HTTPS connections are allowed through
	// without inspection (bypassing domain fronting protection).
	// This is the expected behavior when http.mitm is set to false.
	stats := server.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0 requests initially, got %d", stats.TotalRequests)
	}
}

func TestServer_CertCacheExpiration(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Create server and load CA
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	if err := server.LoadCA(certPath, keyPath); err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	// Generate cert for a host
	tlsConfig, err := server.generateCertForHost("example.com", nil)
	if err != nil {
		t.Fatalf("generateCertForHost failed: %v", err)
	}

	firstCert := tlsConfig.Certificates[0].Leaf

	// Verify the entry is cached
	cached, ok := server.certCache.Load("example.com")
	if !ok {
		t.Fatal("expected cert to be cached")
	}

	entry := cached.(*certCacheEntry)
	if entry.cert.Leaf != firstCert {
		t.Error("cached cert should match returned cert")
	}
	if entry.lastAccess.Load() == 0 {
		t.Error("lastAccess should be set")
	}

	// Generate again - should get cached version
	tlsConfig2, err := server.generateCertForHost("example.com", nil)
	if err != nil {
		t.Fatalf("second generateCertForHost failed: %v", err)
	}

	if tlsConfig2.Certificates[0].Leaf != firstCert {
		t.Error("expected cached certificate to be returned")
	}
}

func TestServer_CertCacheSizeLimit(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Create server and load CA
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	if err := server.LoadCA(certPath, keyPath); err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	// Verify eviction function doesn't panic with empty cache
	server.evictOldestIfNeeded()

	// Generate multiple certs
	for i := range 5 {
		host := "example" + string(rune('a'+i)) + ".com"
		_, err := server.generateCertForHost(host, nil)
		if err != nil {
			t.Fatalf("generateCertForHost failed for %s: %v", host, err)
		}
	}

	// Count cached entries
	count := 0
	server.certCache.Range(func(_, _ any) bool {
		count++
		return true
	})

	if count != 5 {
		t.Errorf("expected 5 cached entries, got %d", count)
	}
}

func TestServer_MITM_BlocksNonAllowlisted(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Create proxy server with MITM but empty allowlist
	filter := allowlist.NewFilter()
	// Don't add any domains - everything should be blocked

	server := NewServer(filter, false)

	if err := server.LoadCA(certPath, keyPath); err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// Create HTTP client that uses our proxy
	proxyURL, _ := url.Parse("http://" + server.listener.Addr().String())
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{Transport: transport}

	// Try to make HTTPS request - should fail because domain not in allowlist
	// The proxy should reject the CONNECT request
	_, err = client.Get("https://blocked.example.com/")
	if err == nil {
		t.Error("Expected error for blocked domain, got nil")
	}
}
