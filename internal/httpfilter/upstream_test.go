package httpfilter

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/cert"
)

// upstreamRecorder collects the targets a test upstream proxy was asked to
// reach: "CONNECT host:port" for tunnels, the absolute URL for forward requests.
type upstreamRecorder struct {
	mu      sync.Mutex
	targets []string
}

func (r *upstreamRecorder) add(t string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets = append(r.targets, t)
}

func (r *upstreamRecorder) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.targets...)
}

// startTestUpstreamProxy runs a minimal recording forward proxy standing in
// for a corporate proxy. CONNECT requests are checked against wantAuth (407 on
// mismatch when set), recorded, answered with exactly "200 OK", then spliced
// byte-for-byte. Absolute-URI requests are recorded and round-tripped with a
// plain client. Returns the proxy URL and the recorder.
func startTestUpstreamProxy(t *testing.T, wantAuth string) (*url.URL, *upstreamRecorder) {
	t.Helper()
	rec := &upstreamRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantAuth != "" && r.Header.Get("Proxy-Authorization") != wantAuth {
			w.Header().Set("Proxy-Authenticate", "Basic")
			http.Error(w, "auth required", http.StatusProxyAuthRequired)
			return
		}
		if r.Method == http.MethodConnect {
			rec.add("CONNECT " + r.Host)
			upstream, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
			if err != nil {
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				_ = upstream.Close()
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				_ = upstream.Close()
				return
			}
			_ = conn.SetDeadline(time.Time{})
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close() }()
			_, _ = io.Copy(conn, upstream)
			_ = conn.Close()
			return
		}
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		rec.add(r.URL.String())
		out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse upstream proxy URL: %v", err)
	}
	return u, rec
}

// injectUpstreamProxy points a not-yet-started Server's proxy resolution at
// upstreamURL for every target. Injection (rather than env vars) is required
// because httpproxy never proxies loopback targets, and all test origins are
// loopback.
func injectUpstreamProxy(server *Server, upstreamURL *url.URL) {
	server.proxyForURL = func(*url.URL) (*url.URL, error) { return upstreamURL, nil }
}

// testProxyViaUpstream mirrors testProxy but injects the upstream proxy
// before Start.
func testProxyViaUpstream(t *testing.T, upstreamCA *x509.CertPool, upstreamURL *url.URL) (caPEM []byte, proxyURL *url.URL) {
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
	server := NewServer(filter, false)
	if err := server.LoadCA(cp, kp); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if upstreamCA != nil {
		server.transport.TLSClientConfig.RootCAs = upstreamCA
	}
	injectUpstreamProxy(server, upstreamURL)
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return caCertPEM, &url.URL{Scheme: "http", Host: server.listener.Addr().String()}
}

func TestUpstream_ForwardProxy_HTTP1(t *testing.T) {
	// Plain-HTTP forward request must traverse the upstream proxy as an
	// absolute-URI request.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	defer ts.Close()
	tsHost := strings.TrimPrefix(ts.URL, "http://")

	upURL, rec := startTestUpstreamProxy(t, "")
	_, proxyURL := testProxyViaUpstream(t, nil, upURL)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://" + tsHost + "/foo")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello from upstream" {
		t.Errorf("status=%d body=%q, want 200 %q", resp.StatusCode, body, "hello from upstream")
	}

	targets := rec.get()
	if len(targets) != 1 || !strings.Contains(targets[0], tsHost+"/foo") {
		t.Errorf("upstream proxy saw %v, want one absolute URL for %s/foo", targets, tsHost)
	}
}

func TestUpstream_Intercept_HTTP1(t *testing.T) {
	// MITM'd HTTPS request: abox's transport must CONNECT through the upstream
	// proxy, then speak TLS to the origin inside that tunnel.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello h1")
	}))
	defer ts.Close()

	upURL, rec := startTestUpstreamProxy(t, "")
	caPEM, proxyURL := testProxyViaUpstream(t, originCAPool(ts), upURL)

	client := clientTrustingAboxCA(t, caPEM, proxyURL, false)
	resp, err := client.Get(ts.URL + "/path")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello h1" {
		t.Errorf("status=%d body=%q, want 200 %q", resp.StatusCode, body, "hello h1")
	}

	tsHost := strings.TrimPrefix(ts.URL, "https://")
	targets := rec.get()
	if len(targets) != 1 || targets[0] != "CONNECT "+tsHost {
		t.Errorf("upstream proxy saw %v, want [CONNECT %s]", targets, tsHost)
	}
}

func TestUpstream_Intercept_HTTP2(t *testing.T) {
	// Same as the h1 case but with an h2 origin: proves ALPN negotiation
	// composes with CONNECT-through-upstream-proxy.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello h2")
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	upURL, rec := startTestUpstreamProxy(t, "")
	caPEM, proxyURL := testProxyViaUpstream(t, originCAPool(ts), upURL)

	client := clientTrustingAboxCA(t, caPEM, proxyURL, true)
	resp, err := client.Get(ts.URL + "/path")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello h2" {
		t.Errorf("status=%d body=%q, want 200 %q", resp.StatusCode, body, "hello h2")
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("response ProtoMajor = %d, want 2", resp.ProtoMajor)
	}
	if targets := rec.get(); len(targets) != 1 || !strings.HasPrefix(targets[0], "CONNECT ") {
		t.Errorf("upstream proxy saw %v, want one CONNECT", targets)
	}
}

// rawConnectThroughAbox opens a raw client conn to a tunnel-mode abox server,
// performs the CONNECT to target, and returns the conn + reader positioned
// at the tunnel start. Fails the test on any error or non-wantStatus reply.
func rawConnectThroughAbox(t *testing.T, server *Server, target string, wantStatus int) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial abox proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, wantStatus)
	}
	return c, br
}

// tunnelEchoServer is a plain-TCP upstream that echoes one byte uppercased.
func tunnelEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				if _, err := c.Read(buf); err != nil {
					return
				}
				buf[0] -= 'a' - 'A'
				_, _ = c.Write(buf)
			}(c)
		}
	}()
	return ln
}

// tunnelModeServer returns a started Server with no MITM CA (CONNECT →
// actionTunnel) and 127.0.0.1 allowlisted.
func tunnelModeServer(t *testing.T) *Server {
	t.Helper()
	filter := allowlist.NewFilter()
	filter.Add("127.0.0.1")
	server := NewServer(filter, false)
	return server
}

func startTunnelModeServer(t *testing.T, server *Server) {
	t.Helper()
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
}

func TestUpstream_Tunnel_ChainsConnect(t *testing.T) {
	// Non-MITM tunnel must chain CONNECT through the upstream proxy instead of
	// dialing the target directly.
	ln := tunnelEchoServer(t)
	target := ln.Addr().String()

	upURL, rec := startTestUpstreamProxy(t, "")
	server := tunnelModeServer(t)
	injectUpstreamProxy(server, upURL)
	startTunnelModeServer(t, server)

	c, br := rawConnectThroughAbox(t, server, target, http.StatusOK)
	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got[0] != 'A' {
		t.Errorf("tunnel echo = %q, want %q", got, "A")
	}
	if targets := rec.get(); len(targets) != 1 || targets[0] != "CONNECT "+target {
		t.Errorf("upstream proxy saw %v, want [CONNECT %s]", targets, target)
	}
}

func TestUpstream_Tunnel_ProxyAuth(t *testing.T) {
	// A userinfo'd proxy URL must produce a basic Proxy-Authorization header on
	// the chained CONNECT. The fake proxy 407s on mismatch, so a missing or
	// wrong header fails deterministically (502 from abox).
	ln := tunnelEchoServer(t)
	target := ln.Addr().String()

	upURL, rec := startTestUpstreamProxy(t, "Basic dTpw") // base64("u:p")
	authURL := *upURL
	authURL.User = url.UserPassword("u", "p")

	server := tunnelModeServer(t)
	injectUpstreamProxy(server, &authURL)
	startTunnelModeServer(t, server)

	c, br := rawConnectThroughAbox(t, server, target, http.StatusOK)
	if _, err := c.Write([]byte("b")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got[0] != 'B' {
		t.Errorf("tunnel echo = %q, want %q", got, "B")
	}
	if targets := rec.get(); len(targets) != 1 || targets[0] != "CONNECT "+target {
		t.Errorf("upstream proxy saw %v, want [CONNECT %s]", targets, target)
	}
}

func TestUpstream_Tunnel_ProxyRefuses_502(t *testing.T) {
	// Upstream proxy refusing the CONNECT (407 here — any non-200) must surface
	// to the client as 502 from abox.
	ln := tunnelEchoServer(t)
	target := ln.Addr().String()

	upURL, _ := startTestUpstreamProxy(t, "Basic dTpw")
	server := tunnelModeServer(t)
	injectUpstreamProxy(server, upURL) // no userinfo → 407 from the fake proxy
	startTunnelModeServer(t, server)

	rawConnectThroughAbox(t, server, target, http.StatusBadGateway)
}

func TestUpstream_DialUpstreamTunnel_NilProxyDialsDirect(t *testing.T) {
	// proxyForURL returning (nil, nil) — no proxy env, no_proxy match, or
	// loopback — must fall through to a direct dial.
	ln := tunnelEchoServer(t)
	server := tunnelModeServer(t)
	server.proxyForURL = func(*url.URL) (*url.URL, error) { return nil, nil } //nolint:nilnil // httpproxy semantics: nil URL = dial direct

	conn, err := server.dialUpstreamTunnel(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("dialUpstreamTunnel: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("c")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got[0] != 'C' {
		t.Errorf("echo = %q, want %q", got, "C")
	}
}

func TestUpstream_NewServer_CapturesEnv(t *testing.T) {
	// NewServer must capture http_proxy/https_proxy/no_proxy at construction.
	// Safe with t.Setenv because httpproxy.FromEnvironment reads env at call
	// time (unlike http.ProxyFromEnvironment's process-wide sync.Once).
	t.Setenv("HTTP_PROXY", "http://corp:3128")
	t.Setenv("HTTPS_PROXY", "http://corp:3128")
	t.Setenv("NO_PROXY", "internal.test")

	server := NewServer(allowlist.NewFilter(), false)

	proxied, err := server.proxyForURL(&url.URL{Scheme: "https", Host: "example.com:443"})
	if err != nil {
		t.Fatalf("proxyForURL: %v", err)
	}
	if proxied == nil || proxied.Host != "corp:3128" {
		t.Errorf("proxyForURL(example.com) = %v, want http://corp:3128", proxied)
	}

	direct, err := server.proxyForURL(&url.URL{Scheme: "https", Host: "internal.test:443"})
	if err != nil {
		t.Fatalf("proxyForURL: %v", err)
	}
	if direct != nil {
		t.Errorf("proxyForURL(internal.test) = %v, want nil (no_proxy)", direct)
	}
}

func TestUpstream_DialViaConnect_BufferedBytesPreserved(t *testing.T) {
	// A proxy that coalesces the CONNECT 200 with early tunnel bytes (e.g. a
	// server-speaks-first protocol relayed eagerly) must not lose those bytes:
	// dialViaConnect wraps the conn so buffered data is read first.
	const early = "EARLY-TUNNEL-BYTES"
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
		// Read the CONNECT request headers (up to the blank line).
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		// Coalesce the 200 with early tunnel bytes in one write.
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n" + early))
	}()

	proxyURL := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialViaConnect(context.Background(), dialer, proxyURL, "ignored.test:443")
	if err != nil {
		t.Fatalf("dialViaConnect: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(early))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read early bytes: %v", err)
	}
	if string(got) != early {
		t.Errorf("early tunnel bytes = %q, want %q", got, early)
	}
}

func TestUpstream_DialUpstreamTunnel_UnsupportedScheme(t *testing.T) {
	server := tunnelModeServer(t)
	badURL := &url.URL{Scheme: "socks4", Host: "127.0.0.1:1080"}
	injectUpstreamProxy(server, badURL)
	_, err := server.dialUpstreamTunnel(context.Background(), "x:443")
	if err == nil || !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Errorf("err = %v, want unsupported proxy scheme", err)
	}
}

// startTestSOCKS5Proxy runs a minimal recording SOCKS5 proxy (RFC 1928/1929).
// When wantUser is "", only the no-auth method is offered; otherwise
// username/password auth is required and verified. CONNECT targets are
// recorded as "SOCKS5 host:port". The returned URL carries userinfo when auth
// is configured.
func startTestSOCKS5Proxy(t *testing.T, wantUser, wantPass string) (*url.URL, *upstreamRecorder) {
	t.Helper()
	rec := &upstreamRecorder{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5Conn(c, rec, wantUser, wantPass)
		}
	}()
	u := &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
	if wantUser != "" {
		u.User = url.UserPassword(wantUser, wantPass)
	}
	return u, rec
}

func serveSOCKS5Conn(c net.Conn, rec *upstreamRecorder, wantUser, wantPass string) {
	defer c.Close()
	br := bufio.NewReader(c)

	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if wantUser != "" {
		// Require username/password (method 2), RFC 1929 subnegotiation.
		_, _ = c.Write([]byte{5, 2})
		sub := make([]byte, 2) // VER ULEN
		if _, err := io.ReadFull(br, sub); err != nil || sub[0] != 1 {
			return
		}
		user := make([]byte, sub[1])
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(br, plen); err != nil {
			return
		}
		pass := make([]byte, plen[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		if string(user) != wantUser || string(pass) != wantPass {
			_, _ = c.Write([]byte{1, 1}) // auth failure
			return
		}
		_, _ = c.Write([]byte{1, 0})
	} else {
		_, _ = c.Write([]byte{5, 0}) // no auth required
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT — only CONNECT (1) handled.
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 5 || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		a := make([]byte, 4)
		if _, err := io.ReadFull(br, a); err != nil {
			return
		}
		host = net.IP(a).String()
	case 3: // domain name
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(br, d); err != nil {
			return
		}
		host = string(d)
	case 4: // IPv6
		a := make([]byte, 16)
		if _, err := io.ReadFull(br, a); err != nil {
			return
		}
		host = net.IP(a).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
	rec.add("SOCKS5 " + target)

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	defer upstream.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // success, bound 0.0.0.0:0
	// Splice from br (not c) — it may hold tunnel bytes read past the request.
	// Half-close (not Close) upstream when the client side ends, so EOF
	// propagates without killing the response direction.
	go func() {
		_, _ = io.Copy(upstream, br)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()
	_, _ = io.Copy(c, upstream)
}

func TestUpstream_Tunnel_SOCKS5(t *testing.T) {
	// Non-MITM tunnel through a socks5:// or socks5h:// upstream proxy —
	// symmetric with the transport path, where stdlib handles both natively.
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			ln := tunnelEchoServer(t)
			target := ln.Addr().String()

			upURL, rec := startTestSOCKS5Proxy(t, "", "")
			upURL.Scheme = scheme
			server := tunnelModeServer(t)
			injectUpstreamProxy(server, upURL)
			startTunnelModeServer(t, server)

			c, br := rawConnectThroughAbox(t, server, target, http.StatusOK)
			if _, err := c.Write([]byte("d")); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, 1)
			if _, err := io.ReadFull(br, got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if got[0] != 'D' {
				t.Errorf("tunnel echo = %q, want %q", got, "D")
			}
			if targets := rec.get(); len(targets) != 1 || targets[0] != "SOCKS5 "+target {
				t.Errorf("socks5 proxy saw %v, want [SOCKS5 %s]", targets, target)
			}
		})
	}
}

func TestUpstream_Tunnel_SOCKS5_HalfClose(t *testing.T) {
	// Client half-close must propagate through a socks5 tunnel to the origin.
	// x/net's socks conn hides the TCP CloseWrite (it embeds the net.Conn
	// interface), so without socksConn the origin below — which reads to EOF
	// before replying — would never answer and this test would time out.
	const msg = "hello"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		all, err := io.ReadAll(c) // blocks until client FIN arrives
		if err != nil {
			return
		}
		_, _ = io.WriteString(c, strings.ToUpper(string(all)))
	}()
	target := ln.Addr().String()

	upURL, _ := startTestSOCKS5Proxy(t, "", "")
	server := tunnelModeServer(t)
	injectUpstreamProxy(server, upURL)
	startTunnelModeServer(t, server)

	c, br := rawConnectThroughAbox(t, server, target, http.StatusOK)
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read reply (half-close likely not propagated): %v", err)
	}
	if string(reply) != strings.ToUpper(msg) {
		t.Errorf("reply = %q, want %q", reply, strings.ToUpper(msg))
	}
}

func TestUpstream_Tunnel_SOCKS5_Auth(t *testing.T) {
	// Userinfo on a socks5:// proxy URL must drive RFC 1929 username/password
	// auth. The fake proxy rejects wrong credentials, so success proves the
	// auth round-trip.
	ln := tunnelEchoServer(t)
	target := ln.Addr().String()

	upURL, rec := startTestSOCKS5Proxy(t, "u", "p")
	server := tunnelModeServer(t)
	injectUpstreamProxy(server, upURL)
	startTunnelModeServer(t, server)

	c, br := rawConnectThroughAbox(t, server, target, http.StatusOK)
	if _, err := c.Write([]byte("e")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got[0] != 'E' {
		t.Errorf("tunnel echo = %q, want %q", got, "E")
	}
	if targets := rec.get(); len(targets) != 1 || targets[0] != "SOCKS5 "+target {
		t.Errorf("socks5 proxy saw %v, want [SOCKS5 %s]", targets, target)
	}
}

func TestUpstream_Tunnel_SOCKS5_BadAuth_502(t *testing.T) {
	// Wrong credentials must fail the SOCKS handshake and surface as 502.
	ln := tunnelEchoServer(t)
	target := ln.Addr().String()

	upURL, _ := startTestSOCKS5Proxy(t, "u", "p")
	badURL := *upURL
	badURL.User = url.UserPassword("u", "wrong")
	server := tunnelModeServer(t)
	injectUpstreamProxy(server, &badURL)
	startTunnelModeServer(t, server)

	rawConnectThroughAbox(t, server, target, http.StatusBadGateway)
}
