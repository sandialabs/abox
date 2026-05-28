package httpfilter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/cert"
)

// testProxy spins up a proxy Server with MITM loaded, allowlists 127.0.0.1
// (so SSRF doesn't block the loopback test origin), and returns:
//   - the abox CA PEM (clients must trust this to do the inner TLS handshake)
//   - the running *Server (poke fields like reverseProxy.ErrorHandler in tests)
//   - a configured *url.URL for the proxy listener
//   - a cleanup func
//
// If upstreamCA is non-nil, it's installed in the proxy's reverse-proxy
// transport so it can verify the test origin's cert.
func testProxy(t *testing.T, upstreamCA *x509.CertPool) (caPEM []byte, server *Server, proxyURL *url.URL, cleanup func()) {
	t.Helper()
	caCertPEM, caKeyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	tmpDir := t.TempDir()
	cp := filepath.Join(tmpDir, "ca.pem")
	kp := filepath.Join(tmpDir, "key.pem")
	_ = os.WriteFile(cp, caCertPEM, 0o644)
	_ = os.WriteFile(kp, caKeyPEM, 0o600)

	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server = NewServer(filter, false)
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if upstreamCA != nil {
		server.transport.TLSClientConfig.RootCAs = upstreamCA
	}
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	proxyURL = &url.URL{Scheme: "http", Host: server.listener.Addr().String()}
	cleanup = func() { _ = server.Shutdown(context.Background()) }
	return caCertPEM, server, proxyURL, cleanup
}

// originCAPool returns a cert pool trusting an httptest server's certificate.
func originCAPool(ts *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return pool
}

// clientTrustingAboxCA returns an http.Client that trusts caPEM (the abox
// MITM CA) and uses proxyURL as its forward proxy. If forceH2 is true the
// client advertises h2 in ALPN; otherwise h1 only.
func clientTrustingAboxCA(t *testing.T, caPEM []byte, proxyURL *url.URL, forceH2 bool) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to append abox CA to pool")
	}
	nextProtos := []string{"http/1.1"}
	if forceH2 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: forceH2,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			NextProtos: nextProtos,
		},
	}
	return &http.Client{Transport: tr}
}

func TestProxy_NotProxyRequest(t *testing.T) {
	_, _, proxyURL, cleanup := testProxy(t, nil)
	defer cleanup()

	// GET /foo (non-absolute URL, not CONNECT) directly to the proxy.
	resp, err := http.Get("http://" + proxyURL.Host + "/foo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestProxy_ConnectReject(t *testing.T) {
	caPEM, _, proxyURL, cleanup := testProxy(t, nil)
	defer cleanup()

	// blocked.example.com is not in the allowlist → decideConnect returns
	// actionReject → 403 on the CONNECT.
	client := clientTrustingAboxCA(t, caPEM, proxyURL, false)
	_, err := client.Get("https://blocked.example.com/")
	if err == nil {
		t.Fatal("expected error for blocked CONNECT, got nil")
	}
	// The Go http.Client wraps the 403 from CONNECT in an error; we just want
	// the request to fail. Exact error text is implementation-defined.
}

func TestProxy_ForwardProxy_HTTP1(t *testing.T) {
	// Plain HTTP forward proxy (GET http://example.com/...).
	// Set up: upstream HTTP origin, abox proxy with origin allowlisted.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	defer ts.Close()

	tsHost := strings.TrimPrefix(ts.URL, "http://")
	_, _, proxyURL, cleanup := testProxy(t, nil) // upstream is plain HTTP, no CA needed
	defer cleanup()

	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("http://" + tsHost + "/foo")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello from upstream" {
		t.Errorf("body = %q, want %q", string(body), "hello from upstream")
	}
}

func TestProxy_Intercept_HTTP1(t *testing.T) {
	// Stand up an HTTPS origin (h1 only).
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello h1")
	}))
	defer ts.Close()

	caPEM, _, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	client := clientTrustingAboxCA(t, caPEM, proxyURL, false)

	resp, err := client.Get(ts.URL + "/path")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello h1" {
		t.Errorf("body = %q, want %q", string(body), "hello h1")
	}
	if got := resp.ProtoMajor; got != 1 {
		t.Errorf("response ProtoMajor = %d, want 1", got)
	}
}

func TestProxy_Intercept_HTTP2(t *testing.T) {
	// Stand up an HTTPS origin with h2 enabled.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello h2")
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	caPEM, _, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	// Client speaks h2 to the proxy AND expects h2 from the proxy.
	client := clientTrustingAboxCA(t, caPEM, proxyURL, true)

	resp, err := client.Get(ts.URL + "/path")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello h2" {
		t.Errorf("body = %q, want %q", string(body), "hello h2")
	}
	if got := resp.ProtoMajor; got != 2 {
		t.Errorf("response ProtoMajor = %d, want 2 (h2 negotiation failed)", got)
	}
}

func TestProxy_Intercept_HTTP2_DomainFronting(t *testing.T) {
	// Origin h2 server.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	caPEM, _, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	// Open a CONNECT to 127.0.0.1 (allowed), but send a request with
	// :authority pointing at notallowed.example.com — should be blocked
	// with 403 even though the CONNECT target was allowed.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			NextProtos: []string{"h2", "http/1.1"},
			ServerName: "127.0.0.1", // CONNECT target SNI
		},
	}
	// Configure the h2 transport so we can override :authority via Host header.
	if err := http2.ConfigureTransport(tr); err != nil {
		t.Fatalf("ConfigureTransport: %v", err)
	}

	client := &http.Client{Transport: tr}
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "notallowed.example.com" // sets :authority for h2
	resp, err := client.Do(req)
	if err != nil {
		// Some clients fail at the proxy level rather than getting a 403 body.
		// Either is an acceptable signal that the request was blocked.
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (domain fronting block)", resp.StatusCode)
	}
}

func TestProxy_NilURLGuard(t *testing.T) {
	// Exercise the public ServeHTTP entry point with a synthetic nil-URL
	// request. Stdlib h1/h2 servers don't deliver nil URLs in practice, but
	// the guard exists so a corrupted test request or future bug doesn't
	// panic the proxy.
	filter := allowlist.NewFilter()
	server := NewServer(filter, false)

	rr := httptest.NewRecorder()
	r := &http.Request{Host: "example.com"} // r.URL intentionally nil
	server.proxyHandler.ServeHTTP(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestProxy_ConnectTunnel(t *testing.T) {
	// Plain TCP upstream — no TLS — to verify byte-for-byte tunnel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Echo: read one byte, write it back uppercased.
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != nil {
			return
		}
		_, _ = c.Write(bytes.ToUpper(buf))
	}()

	// MITM not enabled (no LoadCA) → CONNECT to allowed host → actionTunnel.
	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server := NewServer(filter, false)
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// CONNECT to the proxy.
	proxyConn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()
	target := ln.Addr().String()
	connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Tunnel is up. Write 'a', expect 'A' back (echo handler).
	if _, err := proxyConn.Write([]byte("a")); err != nil {
		t.Fatalf("write 'a': %v", err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got[0] != 'A' {
		t.Errorf("tunnel echo = %q, want %q", got, "A")
	}
}

func TestProxy_ShutdownDrainsInFlightIntercept(t *testing.T) {
	// Verify that Shutdown returns promptly even when an h2 MITM session is
	// in-flight (would otherwise hang because the inner server keeps reading).
	//
	// Origin h2 server that blocks until the request context is cancelled,
	// keeping the stream open.
	streamOpened := make(chan struct{}, 1)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case streamOpened <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	caPEM, server, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	// Override cleanup: we'll Shutdown manually below to time it.
	_ = cleanup
	defer func() { _ = server.Shutdown(context.Background()) }()

	client := clientTrustingAboxCA(t, caPEM, proxyURL, true)

	// Fire a request that the origin handler will not return from.
	reqCtx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	go func() {
		req, _ := http.NewRequestWithContext(reqCtx, "GET", ts.URL+"/", nil)
		_, _ = client.Do(req)
	}()

	// Wait for the origin to see the request, then call Shutdown.
	select {
	case <-streamOpened:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never received the request")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("Shutdown took %v, expected to drain quickly", elapsed)
	}
}
