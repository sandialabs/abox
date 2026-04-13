package dnsfilter

import (
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/sandialabs/abox/internal/allowlist"
)

// mockResponseWriter implements dns.ResponseWriter for testing.
type mockResponseWriter struct {
	msg    *dns.Msg
	remote net.Addr
}

func (w *mockResponseWriter) LocalAddr() net.Addr  { return nil }
func (w *mockResponseWriter) RemoteAddr() net.Addr { return w.remote }
func (w *mockResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}
func (w *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *mockResponseWriter) Close() error              { return nil }
func (w *mockResponseWriter) TsigStatus() error         { return nil }
func (w *mockResponseWriter) TsigTimersOnly(bool)       {}
func (w *mockResponseWriter) Hijack()                   {}

func TestNewServer(t *testing.T) {
	filter := allowlist.NewFilter()

	tests := []struct {
		name     string
		upstream string
		passive  bool
		wantErr  bool
	}{
		{"valid", "8.8.8.8:53", false, false},
		{"valid-passive", "8.8.8.8:53", true, false},
		{"valid-hostname", "dns.google:53", false, false},
		{"valid-no-port", "8.8.8.8", false, false},
		{"empty-upstream", "", false, true},
		{"invalid-port", "8.8.8.8:0", false, true},
		{"invalid-port-high", "8.8.8.8:99999", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(filter, tt.upstream, tt.passive)
			if tt.wantErr {
				if err == nil {
					t.Error("NewServer() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("NewServer() error = %v", err)
				return
			}
			if server == nil {
				t.Fatal("NewServer() returned nil server")
				return
			}
			if server.IsActive() == tt.passive {
				t.Errorf("NewServer() IsActive() = %v, want %v", server.IsActive(), !tt.passive)
			}
		})
	}
}

func TestServer_ServeDNS_Allowed(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("github.com")

	server, err := NewServer(filter, "8.8.8.8:53", false)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Mock resolver to return a successful response
	mockResp := &dns.Msg{}
	mockResp.SetReply(&dns.Msg{})
	mockResp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "github.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("140.82.121.4"),
		},
	}

	mock := &mockResolver{
		ExchangeFunc: func(m *dns.Msg, address string) (*dns.Msg, error) {
			resp := mockResp.Copy()
			resp.SetReply(m)
			return resp, nil
		},
	}
	prev := setResolver(mock)
	defer setResolver(prev)

	// Create request for allowed domain
	req := &dns.Msg{}
	req.SetQuestion("api.github.com.", dns.TypeA)

	w := &mockResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.10.10.2"), Port: 12345}}
	server.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("ServeDNS() did not write response")
	}

	if w.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("ServeDNS() Rcode = %v, want %v", w.msg.Rcode, dns.RcodeSuccess)
	}

	// Verify resolver was called
	if len(mock.Calls) != 1 {
		t.Errorf("Resolver called %d times, want 1", len(mock.Calls))
	}
}

func TestServer_ServeDNS_Blocked(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("github.com")

	server, err := NewServer(filter, "8.8.8.8:53", false)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	mock := &mockResolver{}
	prev := setResolver(mock)
	defer setResolver(prev)

	// Create request for blocked domain
	req := &dns.Msg{}
	req.SetQuestion("google.com.", dns.TypeA)

	w := &mockResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.10.10.2"), Port: 12345}}
	server.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("ServeDNS() did not write response")
	}

	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("ServeDNS() Rcode = %v, want %v (NXDOMAIN)", w.msg.Rcode, dns.RcodeNameError)
	}

	// Verify resolver was NOT called for blocked domain
	if len(mock.Calls) != 0 {
		t.Errorf("Resolver called %d times for blocked domain, want 0", len(mock.Calls))
	}
}

func TestServer_ServeDNS_PassiveMode(t *testing.T) {
	filter := allowlist.NewFilter()
	// Don't add any domains - normally everything would be blocked

	server, err := NewServer(filter, "8.8.8.8:53", true) // passive mode
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	mockResp := &dns.Msg{}
	mockResp.SetReply(&dns.Msg{})

	mock := &mockResolver{
		ExchangeFunc: func(m *dns.Msg, address string) (*dns.Msg, error) {
			resp := mockResp.Copy()
			resp.SetReply(m)
			return resp, nil
		},
	}
	prev := setResolver(mock)
	defer setResolver(prev)

	// Create request for domain not in allowlist
	req := &dns.Msg{}
	req.SetQuestion("google.com.", dns.TypeA)

	w := &mockResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.10.10.2"), Port: 12345}}
	server.ServeDNS(w, req)

	// In passive mode, should be allowed
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("ServeDNS() in passive mode Rcode = %v, want %v", w.msg.Rcode, dns.RcodeSuccess)
	}

	// Resolver should be called
	if len(mock.Calls) != 1 {
		t.Errorf("Resolver called %d times in passive mode, want 1", len(mock.Calls))
	}
}

func TestServer_Stats(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("allowed.com")

	server, err := NewServer(filter, "8.8.8.8:53", false)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	mockResp := &dns.Msg{}
	mockResp.SetReply(&dns.Msg{})

	mock := &mockResolver{
		ExchangeFunc: func(m *dns.Msg, address string) (*dns.Msg, error) {
			resp := mockResp.Copy()
			resp.SetReply(m)
			return resp, nil
		},
	}
	prev := setResolver(mock)
	defer setResolver(prev)

	// Make an allowed request
	req1 := &dns.Msg{}
	req1.SetQuestion("allowed.com.", dns.TypeA)
	w1 := &mockResponseWriter{remote: &net.UDPAddr{}}
	server.ServeDNS(w1, req1)

	// Make a blocked request
	req2 := &dns.Msg{}
	req2.SetQuestion("blocked.com.", dns.TypeA)
	w2 := &mockResponseWriter{remote: &net.UDPAddr{}}
	server.ServeDNS(w2, req2)

	stats := server.GetStats()

	if stats.TotalQueries != 2 {
		t.Errorf("TotalQueries = %d, want 2", stats.TotalQueries)
	}
	if stats.AllowedQueries != 1 {
		t.Errorf("AllowedQueries = %d, want 1", stats.AllowedQueries)
	}
	if stats.BlockedQueries != 1 {
		t.Errorf("BlockedQueries = %d, want 1", stats.BlockedQueries)
	}
}

func TestServer_SetActive(t *testing.T) {
	filter := allowlist.NewFilter()
	server, _ := NewServer(filter, "8.8.8.8:53", false)

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

func TestServer_DNSRebindingBlocked(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("untrusted.com") // Not the domain being queried

	server, err := NewServer(filter, "8.8.8.8:53", false)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Query a domain NOT in the allowlist but allowed via passive mode
	// to test that rebinding protection still applies.
	server.SetActive(false) // passive mode

	tests := []struct {
		name      string
		ip        string
		wantRcode int
	}{
		// Private IPs should be blocked (DNS rebinding attack) even in passive mode
		{"rebind-to-loopback", "127.0.0.1", dns.RcodeServerFailure},
		{"rebind-to-private-10", "10.0.0.1", dns.RcodeServerFailure},
		{"rebind-to-private-192", "192.168.1.1", dns.RcodeServerFailure},
		{"rebind-to-private-172", "172.16.0.1", dns.RcodeServerFailure},
		{"rebind-to-link-local", "169.254.1.1", dns.RcodeServerFailure},

		// Public IPs should be allowed
		{"public-ip-allowed", "8.8.8.8", dns.RcodeSuccess},
		{"public-ip-github", "140.82.121.4", dns.RcodeSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock resolver returns the controlled IP
			mockResp := &dns.Msg{}
			mockResp.SetReply(&dns.Msg{})
			mockResp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "attacker.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP(tt.ip),
				},
			}

			mock := &mockResolver{
				ExchangeFunc: func(m *dns.Msg, address string) (*dns.Msg, error) {
					resp := mockResp.Copy()
					resp.SetReply(m)
					return resp, nil
				},
			}
			prev := setResolver(mock)
			defer setResolver(prev)

			req := &dns.Msg{}
			req.SetQuestion("attacker.com.", dns.TypeA)

			w := &mockResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.10.10.2"), Port: 12345}}
			server.ServeDNS(w, req)

			if w.msg == nil {
				t.Fatal("ServeDNS() did not write response")
			}

			if w.msg.Rcode != tt.wantRcode {
				t.Errorf("ServeDNS() Rcode = %v, want %v", w.msg.Rcode, tt.wantRcode)
			}
		})
	}
}

func TestServer_DNSRebindingSkippedForAllowlisted(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("trusted.internal.com") // Explicitly allowlisted

	server, err := NewServer(filter, "8.8.8.8:53", false)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Allowlisted domain resolving to private IPs should succeed —
	// the user explicitly trusts this domain.
	tests := []struct {
		name string
		ip   string
	}{
		{"private-10", "10.0.5.3"},
		{"private-192", "192.168.1.100"},
		{"private-172", "172.16.0.50"},
		{"loopback", "127.0.0.1"},
		{"link-local", "169.254.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockResp := &dns.Msg{}
			mockResp.SetReply(&dns.Msg{})
			mockResp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "trusted.internal.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP(tt.ip),
				},
			}

			mock := &mockResolver{
				ExchangeFunc: func(m *dns.Msg, address string) (*dns.Msg, error) {
					resp := mockResp.Copy()
					resp.SetReply(m)
					return resp, nil
				},
			}
			prev := setResolver(mock)
			defer setResolver(prev)

			req := &dns.Msg{}
			req.SetQuestion("trusted.internal.com.", dns.TypeA)

			w := &mockResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.10.10.2"), Port: 12345}}
			server.ServeDNS(w, req)

			if w.msg == nil {
				t.Fatal("ServeDNS() did not write response")
			}

			if w.msg.Rcode != dns.RcodeSuccess {
				t.Errorf("ServeDNS() Rcode = %v, want %v (allowlisted domain should skip rebinding check)",
					w.msg.Rcode, dns.RcodeSuccess)
			}
		})
	}
}

func TestServer_DNSRebindingBlocked_IPv6(t *testing.T) {
	filter := allowlist.NewFilter()
	filter.Add("other.com") // Not the domain being queried

	server, err := NewServer(filter, "8.8.8.8:53", false)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Use passive mode so the non-allowlisted domain is forwarded
	server.SetActive(false)

	tests := []struct {
		name      string
		ip        string
		wantRcode int
	}{
		// IPv6 private/link-local should be blocked (not explicitly allowlisted)
		{"rebind-to-ipv6-loopback", "::1", dns.RcodeServerFailure},
		{"rebind-to-ipv6-link-local", "fe80::1", dns.RcodeServerFailure},
		{"rebind-to-ipv6-private", "fc00::1", dns.RcodeServerFailure},

		// IPv6 public should be allowed
		{"public-ipv6-allowed", "2001:4860:4860::8888", dns.RcodeSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockResp := &dns.Msg{}
			mockResp.SetReply(&dns.Msg{})
			mockResp.Answer = []dns.RR{
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "attacker.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP(tt.ip),
				},
			}

			mock := &mockResolver{
				ExchangeFunc: func(m *dns.Msg, address string) (*dns.Msg, error) {
					resp := mockResp.Copy()
					resp.SetReply(m)
					return resp, nil
				},
			}
			prev := setResolver(mock)
			defer setResolver(prev)

			req := &dns.Msg{}
			req.SetQuestion("attacker.com.", dns.TypeAAAA)

			w := &mockResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.10.10.2"), Port: 12345}}
			server.ServeDNS(w, req)

			if w.msg == nil {
				t.Fatal("ServeDNS() did not write response")
			}

			if w.msg.Rcode != tt.wantRcode {
				t.Errorf("ServeDNS() Rcode = %v, want %v", w.msg.Rcode, tt.wantRcode)
			}
		})
	}
}
