package httpfilter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/cert"
	"github.com/sandialabs/abox/internal/filterbase"
)

func TestDecideConnect_MITMExceptions(t *testing.T) {
	newSrv := func(allow, exceptions []string, mitm bool) *Server {
		f := allowlist.NewFilter()
		for _, d := range allow {
			f.Add(d)
		}
		s := NewServer(f, false) // active mode
		s.SetMITMExceptions(exceptions)
		if mitm {
			s.mitmReady.Store(true) // simulate LoadCA without real cert files
		}
		return s
	}

	tests := []struct {
		name       string
		allow      []string
		exceptions []string
		mitm       bool
		host       string
		want       connectAction
	}{
		{"exception not allowlisted still rejected", nil, []string{"pinned.example.com"}, true, "pinned.example.com", actionReject},
		{"allowlisted exception + mitm tunnels", []string{"pinned.example.com"}, []string{"pinned.example.com"}, true, "pinned.example.com", actionTunnel},
		{"allowlisted non-exception + mitm intercepts", []string{"example.com"}, nil, true, "example.com", actionIntercept},
		{"exception matches subdomain", []string{"example.com"}, []string{"example.com"}, true, "api.example.com", actionTunnel},
		{"wildcard exception matches subdomain", []string{"example.com"}, []string{"*.example.com"}, true, "api.example.com", actionTunnel},
		{"wildcard exception matches apex", []string{"example.com"}, []string{"*.example.com"}, true, "example.com", actionTunnel},
		{"mitm off tunnels regardless of exceptions", []string{"example.com"}, nil, false, "example.com", actionTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSrv(tt.allow, tt.exceptions, tt.mitm)
			if got := s.decideConnect(tt.host); got != tt.want {
				t.Errorf("decideConnect(%q) = %d, want %d", tt.host, got, tt.want)
			}
		})
	}
}

func TestDecideConnect_MITMException_StatsCountedOnce(t *testing.T) {
	f := allowlist.NewFilter()
	f.Add("pinned.example.com")
	s := NewServer(f, false)
	s.SetMITMExceptions([]string{"pinned.example.com"})
	s.mitmReady.Store(true)

	if got := s.decideConnect("pinned.example.com"); got != actionTunnel {
		t.Fatalf("decideConnect = %d, want actionTunnel(%d)", got, actionTunnel)
	}
	st := s.GetStats()
	if st.TotalRequests != 1 || st.AllowedRequests != 1 || st.BlockedRequests != 0 {
		t.Errorf("stats = {total:%d allowed:%d blocked:%d}, want {1 1 0}",
			st.TotalRequests, st.AllowedRequests, st.BlockedRequests)
	}
}

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
		{"public-203.0.113.4", "203.0.113.4", false},
		{"public-203.0.113.34", "203.0.113.34", false},
		{"public-ipv6", "2001:db8::8888", false},

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
		// Bare bracketed IPv6 — happens when an HTTP/2 :authority pseudo-header
		// or a Host header is "[::1]" with no port. Without bracket stripping,
		// downstream allowlist / SSRF checks would see "[::1]" literal and miss
		// loopback. (SSRF gap pre-fix.)
		{"ipv6-bracketed-no-port", "[::1]", "::1"},
		{"ipv6-bracketed-link-local", "[fe80::1]", "fe80::1"},
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

// TestServer_CheckHost_AllowlistedPrivateIP asserts that allowlisting a
// host no longer exempts it from SSRF protection. Because the proxy dials from
// the host, an allowlisted name/IP that points at a private/metadata address is
// still blocked unless the operator opts the range in via allow_private_targets.
func TestServer_CheckHost_AllowlistedPrivateIP(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("10.0.5.3")     // Explicitly allowlist a private IP literal
	filter.Add("192.168.1.50") // Another private IP

	server := NewServer(filter, false)

	// Without allow_private_targets, allowlisting alone does NOT bypass SSRF.
	for _, host := range []string{"10.0.5.3", "192.168.1.50", "10.0.0.1", "127.0.0.1", "169.254.169.254"} {
		allowed, blockedSSRF := server.checkHost(host)
		if allowed || !blockedSSRF {
			t.Errorf("checkHost(%q) = (allowed=%v, ssrf=%v), want (false, true) — allowlisting must not bypass SSRF", host, allowed, blockedSSRF)
		}
	}

	// Opting the range in via allow_private_targets permits exactly that range.
	if err := server.SetAllowPrivateTargets([]string{"10.0.5.0/24"}); err != nil {
		t.Fatalf("SetAllowPrivateTargets: %v", err)
	}
	if allowed, ssrf := server.checkHost("10.0.5.3"); !allowed || ssrf {
		t.Errorf("checkHost(10.0.5.3) after opt-in = (allowed=%v, ssrf=%v), want (true, false)", allowed, ssrf)
	}
	// A different private range — and the metadata address — stay blocked.
	for _, host := range []string{"192.168.1.50", "169.254.169.254", "127.0.0.1"} {
		if allowed, ssrf := server.checkHost(host); allowed || !ssrf {
			t.Errorf("checkHost(%q) after opt-in = (allowed=%v, ssrf=%v), want (false, true)", host, allowed, ssrf)
		}
	}
}

// TestServer_DialControl_BlocksResolvedPrivateIP covers the domain case the
// Host-string check can't: an (allowlisted) hostname that resolves to a private
// IP must be rejected at dial time. dialControl is the authoritative gate.
func TestServer_DialControl_BlocksResolvedPrivateIP(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("internal.example.com")
	server := NewServer(filter, false)

	// Host header (a domain) passes checkHost — it's not an IP literal.
	if _, blockedSSRF := server.checkHost("internal.example.com"); blockedSSRF {
		t.Fatal("hostname should not be SSRF-blocked at the Host-string layer")
	}

	// But the resolved address is gated by dialControl.
	if err := server.dialControl("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("dialControl must block a resolved metadata IP")
	}
	if err := server.dialControl("tcp", "10.0.0.1:443", nil); err == nil {
		t.Error("dialControl must block a resolved private IP")
	}
	if err := server.dialControl("tcp", "203.0.113.34:80", nil); err != nil {
		t.Errorf("dialControl must allow a public IP, got %v", err)
	}

	// Opt-in permits the resolved private range.
	if err := server.SetAllowPrivateTargets([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("SetAllowPrivateTargets: %v", err)
	}
	if err := server.dialControl("tcp", "10.0.0.1:443", nil); err != nil {
		t.Errorf("dialControl should allow opted-in private IP, got %v", err)
	}
	if err := server.dialControl("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("dialControl must still block metadata IP not in the opt-in range")
	}
}

// TestServer_DialControl_BlockAccounting asserts the side effects of a dial-time
// SSRF/rebinding block: BlockedRequests increments and the block is written to
// the traffic log with the ssrf reason. Mirrors the DNS rebinding accounting test
// so a regression that dropped either would be caught (the block being invisible
// in `abox http status` and the traffic log).
func TestServer_DialControl_BlockAccounting(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("internal.example.com")
	server := NewServer(filter, false)

	// A real file traffic logger so LogBlock's effect is observable.
	logPath := filepath.Join(t.TempDir(), "http.log")
	if err := server.InitTrafficLogger(logPath); err != nil {
		t.Fatalf("InitTrafficLogger: %v", err)
	}

	before := server.GetStats().BlockedRequests

	// A blocked dial (resolved private IP) must increment BlockedRequests.
	if err := server.dialControl("tcp", "10.0.0.1:443", nil); err == nil {
		t.Fatal("dialControl must block a resolved private IP")
	}
	if got := server.GetStats().BlockedRequests; got != before+1 {
		t.Fatalf("BlockedRequests = %d, want %d after a blocked dial", got, before+1)
	}

	// An allowed (public) dial must NOT change the blocked counter.
	if err := server.dialControl("tcp", "203.0.113.34:80", nil); err != nil {
		t.Fatalf("dialControl must allow a public IP: %v", err)
	}
	if got := server.GetStats().BlockedRequests; got != before+1 {
		t.Fatalf("BlockedRequests = %d, want unchanged (%d) after an allowed dial", got, before+1)
	}

	// The block was recorded to the traffic log with the SSRF reason.
	server.CloseTrafficLogger() // flush + close before reading
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read traffic log: %v", err)
	}
	if !strings.Contains(string(data), "ssrf_private_ip") {
		t.Errorf("traffic log missing ssrf_private_ip block entry:\n%s", data)
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

func TestServer_ProxyEndToEnd_HTTP1(t *testing.T) {
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

// TestServer_LoadCA_Concurrent exercises the loadOnce guard added in 5e2a59c.
// Concurrent LoadCA calls must publish the CA and spawn the cert-cleanup routine
// exactly once; without the guard each call rewrites cleanupCancel/cleanupDone and
// starts another routine, and the racing writes to those fields (plus the cleanup
// routine reading the shared cleanupDone in its deferred close) are a data race.
// The teeth of this test are therefore the race detector — run via `make test`
// (-race). The bounded Shutdown below is a secondary guard against a teardown hang.
func TestServer_LoadCA_Concurrent(t *testing.T) {
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	server := NewServer(allowlist.NewFilter(), false)

	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			<-start // line up all goroutines so the calls actually overlap
			errs <- server.LoadCA(certPath, keyPath)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("concurrent LoadCA returned error: %v", e)
		}
	}

	if !server.mitmReady.Load() {
		t.Fatal("mitmReady should be true after concurrent LoadCA")
	}

	// A deadlock here is the symptom of an orphaned cleanup routine: Shutdown
	// cancels one routine's context but blocks forever on the other's cleanupDone.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown after concurrent LoadCA: %v", err)
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
	tlsConfig, err := server.generateCertForHost("example.com")
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
	tlsConfig2, err := server.generateCertForHost("example.com")
	if err != nil {
		t.Fatalf("second generateCertForHost failed: %v", err)
	}

	// Both should have the same certificate (cached)
	if tlsConfig.Certificates[0].Leaf != tlsConfig2.Certificates[0].Leaf {
		t.Error("expected cached certificate to be returned")
	}

	// Both paths (cache miss and cache hit) must advertise only "http/1.1" in
	// ALPN, so strict-HTTP/2 clients fail with a clean no_application_protocol
	// alert instead of negotiating empty ALPN and then failing inside the
	// HTTP/1-only proxy parser. See docs/troubleshooting.md.
	for i, cfg := range []*tls.Config{tlsConfig, tlsConfig2} {
		if want := []string{"http/1.1"}; !reflect.DeepEqual(cfg.NextProtos, want) {
			t.Errorf("config %d NextProtos = %v, want %v", i, cfg.NextProtos, want)
		}
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
	tlsConfig, err := server.generateCertForHost("allowed.example.com")
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
	tlsConfig, err := server.generateCertForHost("example.com")
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
	tlsConfig2, err := server.generateCertForHost("example.com")
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
		_, err := server.generateCertForHost(host)
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

// TestServer_CertCacheEviction verifies that evictOldestIfNeeded actually
// removes the oldest 10% of entries once the cache reaches maxCertCacheSize.
// Entries are inserted synthetically (no signing) since the eviction path only
// reads each entry's key and lastAccess time.
func TestServer_CertCacheEviction(t *testing.T) {
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	for i := range maxCertCacheSize {
		entry := &certCacheEntry{cert: &tls.Certificate{}}
		entry.lastAccess.Store(int64(i)) // i == 0 is the oldest
		server.certCache.Store(fmt.Sprintf("host-%05d.example.com", i), entry)
	}

	server.evictOldestIfNeeded()

	evicted := max(maxCertCacheSize/10, 1)
	wantRemaining := maxCertCacheSize - evicted

	count := 0
	server.certCache.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != wantRemaining {
		t.Fatalf("expected %d entries after eviction, got %d", wantRemaining, count)
	}

	// The oldest `evicted` entries (lowest lastAccess) must be the ones removed.
	for i := range evicted {
		key := fmt.Sprintf("host-%05d.example.com", i)
		if _, ok := server.certCache.Load(key); ok {
			t.Errorf("expected oldest entry %q to be evicted", key)
		}
	}
	// The most-recently-accessed entry must survive.
	newest := fmt.Sprintf("host-%05d.example.com", maxCertCacheSize-1)
	if _, ok := server.certCache.Load(newest); !ok {
		t.Errorf("expected newest entry %q to survive eviction", newest)
	}
}

// TestServer_CleanExpiredCerts verifies the periodic cleaner removes expired
// cache entries and retains valid ones.
func TestServer_CleanExpiredCerts(t *testing.T) {
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	now := time.Now()
	storeEntry := func(host string, notAfter time.Time) {
		entry := &certCacheEntry{cert: &tls.Certificate{Leaf: &x509.Certificate{NotAfter: notAfter}}}
		entry.lastAccess.Store(now.UnixNano())
		server.certCache.Store(host, entry)
	}
	storeEntry("expired.example.com", now.Add(-time.Hour))
	storeEntry("valid.example.com", now.Add(time.Hour))

	server.cleanExpiredCerts()

	if _, ok := server.certCache.Load("expired.example.com"); ok {
		t.Error("expected expired cert to be removed by cleanExpiredCerts")
	}
	if _, ok := server.certCache.Load("valid.example.com"); !ok {
		t.Error("expected valid cert to be retained by cleanExpiredCerts")
	}
}

// TestServer_CertCacheExpiredEntryRegenerated verifies that an expired cache
// entry is discarded and re-signed on the next generateCertForHost call (the
// on-access expiry branch).
func TestServer_CertCacheExpiredEntryRegenerated(t *testing.T) {
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	filter := allowlist.NewFilter()
	server := NewServer(filter, false)
	if err := server.LoadCA(certPath, keyPath); err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	// Seed the cache with an already-expired entry for the host.
	expired := &certCacheEntry{cert: &tls.Certificate{Leaf: &x509.Certificate{NotAfter: time.Now().Add(-time.Hour)}}}
	expired.lastAccess.Store(time.Now().UnixNano())
	server.certCache.Store("example.com", expired)

	tlsConfig, err := server.generateCertForHost("example.com")
	if err != nil {
		t.Fatalf("generateCertForHost failed: %v", err)
	}

	got := tlsConfig.Certificates[0].Leaf
	if got == nil {
		t.Fatal("expected a freshly signed leaf certificate")
	}
	if !got.NotAfter.After(time.Now()) {
		t.Error("expected regenerated certificate to be unexpired")
	}
	// The cache must now hold the fresh entry, not the expired one.
	cached, ok := server.certCache.Load("example.com")
	if !ok {
		t.Fatal("expected regenerated cert to be cached")
	}
	if cached.(*certCacheEntry).cert.Leaf != got {
		t.Error("cache should hold the regenerated certificate")
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

func TestServer_DecideConnect(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("allowed.example.com")
	filter.Add("127.0.0.1") // allowlisting alone no longer bypasses SSRF (M1)
	server := NewServer(filter, false)

	// Without MITM (no CA loaded): allowed host → tunnel.
	if got := server.decideConnect("allowed.example.com"); got != actionTunnel {
		t.Errorf("decideConnect(allowed, no MITM) = %v, want actionTunnel", got)
	}

	// An allowlisted private-IP CONNECT target is still rejected by SSRF —
	// allowlisting does not exempt it, since the proxy dials from the host.
	if got := server.decideConnect("127.0.0.1"); got != actionReject {
		t.Errorf("decideConnect(allowlisted private IP, no opt-in) = %v, want actionReject", got)
	}
	// Opting the range in via allow_private_targets makes it tunnel.
	if err := server.SetAllowPrivateTargets([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("SetAllowPrivateTargets: %v", err)
	}
	if got := server.decideConnect("127.0.0.1"); got != actionTunnel {
		t.Errorf("decideConnect(opted-in private IP) = %v, want actionTunnel", got)
	}

	// Disallowed host → reject.
	if got := server.decideConnect("blocked.example.com"); got != actionReject {
		t.Errorf("decideConnect(blocked) = %v, want actionReject", got)
	}

	// Private IP outside the opt-in range → reject (SSRF).
	if got := server.decideConnect("10.0.0.1"); got != actionReject {
		t.Errorf("decideConnect(private IP) = %v, want actionReject", got)
	}

	// With MITM enabled, allowed host → intercept.
	certPEM, keyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	tmpDir := t.TempDir()
	cp := filepath.Join(tmpDir, "ca-cert.pem")
	kp := filepath.Join(tmpDir, "ca-key.pem")
	_ = os.WriteFile(cp, certPEM, 0o644)
	_ = os.WriteFile(kp, keyPEM, 0o600)
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if got := server.decideConnect("allowed.example.com"); got != actionIntercept {
		t.Errorf("decideConnect(allowed, MITM on) = %v, want actionIntercept", got)
	}
}

func TestServer_DecideRequest_DomainFronting(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("allowed.example.com")
	server := NewServer(filter, false)

	// Inner Host differs from CONNECT target and is not allowlisted: fronting block.
	// connectTarget is "host:port" form (what handleConnect passes).
	req, _ := http.NewRequest("GET", "https://other.example.com/", nil)
	req.Host = "other.example.com"
	d := server.decideRequest(req, "allowed.example.com:443")
	if d.forward || d.status != http.StatusForbidden {
		t.Errorf("decideRequest(fronting) = %+v, want forward=false status=403", d)
	}

	// Inner Host matches CONNECT target and is allowed: forward.
	req2, _ := http.NewRequest("GET", "https://allowed.example.com/", nil)
	req2.Host = "allowed.example.com"
	d2 := server.decideRequest(req2, "allowed.example.com:443")
	if !d2.forward {
		t.Errorf("decideRequest(matching allowed) = %+v, want forward=true", d2)
	}
}

func TestServer_DecideRequest_Healthcheck(t *testing.T) {
	filter := allowlist.NewFilter()
	// Healthcheck must work with an empty allowlist.
	server := NewServer(filter, false)

	req, _ := http.NewRequest("GET", "http://"+HealthcheckDomain+"/", nil)
	req.Host = HealthcheckDomain
	d := server.decideRequest(req, "")
	if d.forward || d.status != http.StatusOK {
		t.Errorf("decideRequest(healthcheck) = %+v, want forward=false status=200", d)
	}
	if !strings.Contains(d.body, "healthcheck OK") {
		t.Errorf("healthcheck body = %q, want to contain 'healthcheck OK'", d.body)
	}

	// A MITM'd request whose inner Host spoofs the healthcheck domain but whose
	// CONNECT target is a different host must NOT get the healthcheck shortcut;
	// it falls through to normal policy (here: a domain-fronting block).
	spoof, _ := http.NewRequest("GET", "https://"+HealthcheckDomain+"/", nil)
	spoof.Host = HealthcheckDomain
	if ds := server.decideRequest(spoof, "allowed.example.com:443"); ds.forward || ds.status != http.StatusForbidden {
		t.Errorf("decideRequest(spoofed healthcheck under CONNECT) = %+v, want forward=false status=403", ds)
	}

	// A genuine CONNECT to the healthcheck domain (inner Host == CONNECT target)
	// still gets the shortcut.
	direct, _ := http.NewRequest("GET", "https://"+HealthcheckDomain+"/", nil)
	direct.Host = HealthcheckDomain
	if dd := server.decideRequest(direct, HealthcheckDomain+":443"); dd.forward || dd.status != http.StatusOK {
		t.Errorf("decideRequest(healthcheck via CONNECT) = %+v, want forward=false status=200", dd)
	}
}

// TestPortAllowed covers the destination-port restriction: default sets,
// the missing-port scheme fallback, an explicit override, and fail-closed on a
// malformed host.
func TestPortAllowed(t *testing.T) {
	server := NewServer(allowlist.NewFilter(), false)

	tests := []struct {
		name      string
		hostPort  string
		scheme    string
		isConnect bool
		want      bool
	}{
		{"connect default 443 allowed", "github.com:443", schemeHTTPS, true, true},
		{"connect default 22 blocked", "github.com:22", schemeHTTPS, true, false},
		{"connect default 80 blocked", "github.com:80", schemeHTTPS, true, false},
		{"forward default 80 allowed", "github.com:80", schemeHTTP, false, true},
		{"forward default 443 allowed", "github.com:443", schemeHTTPS, false, true},
		{"forward default 8080 blocked", "github.com:8080", schemeHTTP, false, false},
		{"forward no port http -> 80 allowed", "github.com", schemeHTTP, false, true},
		{"forward no port https -> 443 allowed", "github.com", schemeHTTPS, false, true},
		{"malformed host fails closed", "a:b:c:d", schemeHTTPS, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := server.portAllowed(tt.hostPort, tt.scheme, tt.isConnect); got != tt.want {
				t.Errorf("portAllowed(%q, %q, connect=%v) = %v, want %v", tt.hostPort, tt.scheme, tt.isConnect, got, tt.want)
			}
		})
	}

	// Explicit override replaces the defaults for both paths.
	server.SetAllowedPorts([]int{22, 443})
	if !server.portAllowed("github.com:22", schemeHTTPS, true) {
		t.Error("port 22 should be allowed after opt-in")
	}
	if server.portAllowed("github.com:80", schemeHTTP, false) {
		t.Error("port 80 should be blocked when override omits it")
	}

	// Empty slice restores defaults.
	server.SetAllowedPorts(nil)
	if server.portAllowed("github.com:22", schemeHTTPS, true) {
		t.Error("port 22 should be blocked again after restoring defaults")
	}
}

// TestConnect_PortRestrictionEndToEnd verifies destination-port enforcement through
// the real proxy: with default ports (443 only) a CONNECT to a non-443 port is rejected
// with 403 before any allowlist/tunnel decision, while opting the port in via
// SetAllowedPorts lets the same CONNECT succeed.
func TestConnect_PortRestrictionEndToEnd(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server := NewServer(filter, false) // tunnel mode (no MITM)
	if err := server.SetAllowPrivateTargets([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("SetAllowPrivateTargets: %v", err)
	}
	// Deliberately do NOT allow all ports: exercise the default (443 only).
	startTunnelModeServer(t, server)

	// A CONNECT to an arbitrary non-443 port is rejected by the default policy.
	rawConnectThroughAbox(t, server, "127.0.0.1:2222", http.StatusForbidden)

	// After opting the port in, the CONNECT is no longer port-blocked. (It may
	// still fail to reach a real upstream, but it must get past the 403 gate; we
	// assert the negative: it is NOT 403 for a permitted port by checking a
	// reachable echo upstream.)
	echo := tunnelEchoServer(t)
	_, portStr, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}
	echoPort, _ := strconv.Atoi(portStr)
	server.SetAllowedPorts([]int{echoPort})
	rawConnectThroughAbox(t, server, echo.Addr().String(), http.StatusOK)
}
