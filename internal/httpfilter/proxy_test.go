package httpfilter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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

func TestProxy_Intercept_HTTP1_DomainFronting(t *testing.T) {
	// Same fronting block as the h2 case, over HTTP/1.1: CONNECT to an allowed
	// host (127.0.0.1), inner Host header pointing at a non-allowlisted host.
	// The post-MITM handler is shared across h1/h2, so this proves the verdict
	// holds on the h1 wire path too, not just at the decideRequest unit level.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer ts.Close()

	caPEM, _, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	client := clientTrustingAboxCA(t, caPEM, proxyURL, false) // h1 only
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "notallowed.example.com" // inner Host != CONNECT target
	resp, err := client.Do(req)
	if err != nil {
		// Blocked at the proxy layer rather than a 403 body is also acceptable.
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (domain fronting block over h1)", resp.StatusCode)
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
	defer func() { _ = ln.Close() }()
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
	reqCtx, cancelReq := context.WithCancel(t.Context())
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

func TestProxy_Intercept_SlowHandshakeTimesOut(t *testing.T) {
	// A client that completes CONNECT but never sends the inner ClientHello must
	// not pin the intercept goroutine + conn for the server's lifetime. The
	// bounded handshake deadline aborts it, freeing the activeConns slot.
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
	server := NewServer(filter, false)
	// Set the handshake timeout BEFORE Start so the serve goroutine observes the
	// final value — setting it on an already-running server would be a data race.
	server.handshakeTimeout = 100 * time.Millisecond
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// CONNECT to an allowed target, read the 200, then send NO TLS bytes.
	proxyConn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()
	target := "127.0.0.1:443"
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

	// (1) The proxy aborts the stalled handshake and closes our conn ~100ms in.
	// The 2s read deadline is only a safety net: it must be the *server* closing
	// (EOF), not our deadline firing. Without the handshake timeout the server
	// would hold the conn open and this Read would time out instead — which is
	// what makes this assertion catch the regression rather than mask it.
	_ = proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := br.Read(make([]byte, 1))
	if readErr == nil {
		t.Fatal("expected proxy to close the conn after the handshake timeout, got data")
	}
	var ne net.Error
	if errors.As(readErr, &ne) && ne.Timeout() {
		t.Fatalf("conn not closed within the handshake timeout (client read timed out instead): %v", readErr)
	}

	// (2) Shutdown must drain promptly. This proves the activeConns slot was
	// released (trackedConn.Close→onClose→Done ran); a closed client conn alone
	// doesn't prove that.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned error (activeConns not drained?): %v", err)
	}
}

func TestProxy_Intercept_SlowHeadersTimesOut(t *testing.T) {
	// After the inner TLS handshake completes, a client that opens an h1 request
	// but never finishes sending headers must not pin the intercept goroutine +
	// conn. The inner h1 server's ReadHeaderTimeout (server.go:163) bounds it.
	// Without that timeout the server would block reading headers until Shutdown,
	// and the assertion below (client read must not be what times out) would fail.
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
	server := NewServer(filter, false)
	// Shrink the header-read deadline BEFORE Start so the intercept goroutine
	// (which reads http1Server.ReadHeaderTimeout per-call) observes the final
	// value without a data race.
	server.http1Server.ReadHeaderTimeout = 150 * time.Millisecond
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// CONNECT to an allowed target and read the 200.
	proxyConn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()
	target := "127.0.0.1:443"
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

	// Complete the inner TLS handshake, forcing the h1 path via ALPN. The CONNECT
	// 200 has no body, so the bufio.Reader buffered nothing past the headers and
	// proxyConn is safe to hand to tls.Client.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("append abox CA")
	}
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}

	// Send a request line + one header but never the terminating blank line, then
	// stall. The server's ReadHeaderTimeout should fire and tear the conn down.
	if _, err := tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")); err != nil {
		t.Fatalf("write partial headers: %v", err)
	}

	// The 2s deadline is a safety net only: it must be the *server* ending the
	// read (EOF on close, or a 408 it writes back), not our deadline firing.
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := tlsConn.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(readErr, &ne) && ne.Timeout() {
		t.Fatalf("inner h1 conn not closed within ReadHeaderTimeout (client read timed out instead): %v", readErr)
	}
}

func TestProxy_StalledConnects_NoLeak(t *testing.T) {
	// A burst of clients that complete CONNECT but never send the inner
	// ClientHello must not permanently pin goroutines/conns. The handshake
	// deadline aborts each stalled intercept; afterwards the goroutine count must
	// return to baseline. This extends the single-conn SlowHandshake case to the
	// DoS-burst scenario the bounded handshake was added (5e2a59c) to defend.
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
	server := NewServer(filter, false)
	server.handshakeTimeout = 200 * time.Millisecond
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()

	// Let the server's accept/serve goroutines settle, then take the baseline.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	const burst = 200
	conns := make([]net.Conn, 0, burst)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	addr := server.listener.Addr().String()
	connectReq := "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"
	for i := range burst {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
		if _, err := c.Write([]byte(connectReq)); err != nil {
			t.Fatalf("write CONNECT %d: %v", i, err)
		}
		// Read the 200 so we know the conn reached intercept (and is now blocked
		// on the inner handshake), then send NO TLS bytes.
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("read CONNECT response %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT %d status = %d, want 200", i, resp.StatusCode)
		}
	}

	// After the handshake deadline elapses, every stalled intercept must tear
	// down. Poll (the timeout fires asynchronously) until goroutines drain back
	// near baseline. slack absorbs scheduler/GC goroutines and any not-yet-reaped
	// serve goroutines; the leak (≈2 goroutines/conn × 200) is far larger.
	const slack = 30
	deadline := time.Now().Add(5 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		runtime.GC()
		got = runtime.NumGoroutine()
		if got <= baseline+slack {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got > baseline+slack {
		t.Fatalf("goroutines did not drain after stalled CONNECT burst: baseline=%d, got=%d (leak suspected)", baseline, got)
	}
}

// echoSinkListener accepts connections and discards everything read, used as a
// throwaway tunnel upstream.
func echoSinkListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c); _ = c.Close() }(c)
		}
	}()
	return ln
}

func TestProxy_MaxConns_Queues(t *testing.T) {
	// With a cap of 1, a second client connection must not be served until the
	// first is released — LimitListener queues the second Accept.
	upstream := echoSinkListener(t)
	defer func() { _ = upstream.Close() }()
	target := upstream.Addr().String()

	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server := NewServer(filter, false) // no MITM → tunnel mode
	server.maxConns = 1                // set before Start (avoids racing the serve goroutine)
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()
	addr := server.listener.Addr().String()

	connect := func(c net.Conn) *bufio.Reader {
		_, _ = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
		return bufio.NewReader(c)
	}

	// Conn 1 takes the only slot and holds it open.
	c1, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.Close()
	br1 := connect(c1)
	if resp, err := http.ReadResponse(br1, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("c1 CONNECT: err=%v resp=%v", err, resp)
	}

	// Conn 2 should NOT be served while c1 holds the slot.
	c2, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	defer c2.Close()
	br2 := connect(c2)
	_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := http.ReadResponse(br2, nil); err == nil {
		t.Fatal("c2 was served while c1 held the only slot — cap not enforced")
	}

	// Release c1; the queued c2 must now be served.
	_ = c1.Close()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br2, nil)
	if err != nil {
		t.Fatalf("c2 not served after c1 closed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("c2 status = %d, want 200", resp.StatusCode)
	}
}

func TestProxy_Tunnel_HalfClose_NoTruncation(t *testing.T) {
	// Upstream replies only AFTER the client finishes uploading (client
	// half-closes its send direction). The proxy must keep the response
	// direction alive instead of tearing both down when the upload ends.
	const payload = "FINAL-RESPONSE-PAYLOAD"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c) // drain until the client half-closes (EOF)
		_, _ = c.Write([]byte(payload))
	}()

	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server := NewServer(filter, false) // tunnel mode
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()
	target := ln.Addr().String()

	c, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: err=%v resp=%v", err, resp)
	}

	// Upload, then half-close client→proxy so the upstream's read returns EOF.
	if _, err := c.Write([]byte("client upload")); err != nil {
		t.Fatalf("write upload: %v", err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The response is sent by the upstream only after our upload finished. It
	// must arrive in full — not be truncated by the proxy closing both halves.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(br)
	if string(got) != payload {
		t.Errorf("got %q, want %q (response truncated when upload direction ended)", got, payload)
	}
}

func TestProxy_Tunnel_HalfClose_ClientGetsEOF(t *testing.T) {
	// Upstream sends a response then half-closes its write side, but the client
	// never closes its upload side (read-until-close client). The proxy must
	// propagate the upstream's FIN to the client — even through the connection
	// limiter wrapper (default cap is on), which netutil's wrapper would not.
	const payload = "RESPONSE-THEN-HALF-CLOSE"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte(payload))
		_ = c.(*net.TCPConn).CloseWrite() // half-close upstream→proxy
		_, _ = io.Copy(io.Discard, c)     // keep reading until the client goes away
	}()

	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server := NewServer(filter, false) // default cap (512) → client conn is wrapped
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()
	target := ln.Addr().String()

	c, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: err=%v resp=%v", err, resp)
	}

	// Read until EOF WITHOUT half-closing our upload side. The download FIN must
	// arrive via the proxy forwarding the upstream's CloseWrite; if it doesn't
	// propagate through the limiter wrapper, this read times out (hang).
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(br)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("client never received EOF — upstream half-close did not propagate through the limiter wrapper")
	}
	if string(got) != payload {
		t.Errorf("got %q, want %q", got, payload)
	}
}

func TestProxy_Intercept_HTTP2_FrontingAllowedLogged(t *testing.T) {
	// CONNECT to an allowlisted host, inner :authority a *different* but also
	// allowlisted host. The request is allowed (forwarded to the CONNECT
	// target) but the cross-origin mismatch must be recorded in the traffic log.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	caCertPEM, caKeyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	tmp := t.TempDir()
	cp := filepath.Join(tmp, "ca.pem")
	kp := filepath.Join(tmp, "key.pem")
	_ = os.WriteFile(cp, caCertPEM, 0o644)
	_ = os.WriteFile(kp, caKeyPEM, 0o600)

	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")        // CONNECT target
	filter.Add("alt.allowed.test") // inner :authority (also allowed)
	server := NewServer(filter, false)
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	server.transport.TLSClientConfig.RootCAs = originCAPool(ts)
	trafficLog := filepath.Join(tmp, "traffic.log")
	if err := server.InitTrafficLogger(trafficLog); err != nil {
		t.Fatalf("InitTrafficLogger: %v", err)
	}
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()
	proxyURL := &url.URL{Scheme: "http", Host: server.listener.Addr().String()}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			NextProtos: []string{"h2", "http/1.1"},
			ServerName: "127.0.0.1", // CONNECT target SNI
		},
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		t.Fatalf("ConfigureTransport: %v", err)
	}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = "alt.allowed.test" // sets :authority, != CONNECT target
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (cross-origin allow)", resp.StatusCode)
	}

	// Flush the traffic log and assert the allowed cross-origin mismatch is recorded.
	server.CloseTrafficLogger()
	data, err := os.ReadFile(trafficLog)
	if err != nil {
		t.Fatalf("read traffic log: %v", err)
	}
	if !strings.Contains(string(data), "cross_origin_allowed") {
		t.Errorf("traffic log missing cross_origin_allowed reason:\n%s", data)
	}
}

func TestProxy_TrafficLog_HTTP1(t *testing.T) {
	// Allow and block decisions on the HTTP/1.1 path must be recorded in the
	// traffic log with method/URL/reason — today only the h2 cross-origin line is
	// asserted. One allowed HTTPS request (CONNECT to 127.0.0.1) and one blocked
	// forward-proxy request (off-allowlist http host) should each produce an entry.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer ts.Close()

	caCertPEM, caKeyPEM, err := cert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	tmp := t.TempDir()
	cp := filepath.Join(tmp, "ca.pem")
	kp := filepath.Join(tmp, "key.pem")
	_ = os.WriteFile(cp, caCertPEM, 0o644)
	_ = os.WriteFile(kp, caKeyPEM, 0o600)

	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server := NewServer(filter, false)
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	server.transport.TLSClientConfig.RootCAs = originCAPool(ts)
	trafficLog := filepath.Join(tmp, "traffic.log")
	if err := server.InitTrafficLogger(trafficLog); err != nil {
		t.Fatalf("InitTrafficLogger: %v", err)
	}
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()
	proxyURL := &url.URL{Scheme: "http", Host: server.listener.Addr().String()}

	// Allowed: HTTPS GET to the allowlisted CONNECT target.
	client := clientTrustingAboxCA(t, caCertPEM, proxyURL, false)
	if resp, err := client.Get(ts.URL + "/allowed-path"); err != nil {
		t.Fatalf("allowed GET: %v", err)
	} else {
		_ = resp.Body.Close()
	}

	// Blocked: forward-proxy GET to an off-allowlist http host (rejected before
	// any upstream dial, so no real origin is needed).
	if resp, err := client.Get("http://notallowed.example.com/blocked-path"); err != nil {
		t.Fatalf("blocked GET (transport error, want 403 body): %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("blocked request status = %d, want 403", resp.StatusCode)
		}
	}

	server.CloseTrafficLogger()
	data, err := os.ReadFile(trafficLog)
	if err != nil {
		t.Fatalf("read traffic log: %v", err)
	}

	var sawAllow, sawBlock bool
	for line := range bytes.SplitSeq(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var e struct {
			Action, Domain, Reason, Method, URL string
		}
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal traffic line %q: %v", line, err)
		}
		if e.Action == "allow" && e.Domain == "127.0.0.1" && e.Method == "GET" && strings.Contains(e.URL, "allowed-path") {
			sawAllow = true
		}
		if e.Action == "block" && e.Domain == "notallowed.example.com" && e.Reason == "not_in_allowlist" && e.Method == "GET" && strings.Contains(e.URL, "blocked-path") {
			sawBlock = true
		}
	}
	if !sawAllow {
		t.Errorf("traffic log missing h1 allow entry (domain/method/url):\n%s", data)
	}
	if !sawBlock {
		t.Errorf("traffic log missing h1 block entry (not_in_allowlist + method/url):\n%s", data)
	}
}
