package httpfilter

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProxy_WebSocket_Upgrade verifies that an HTTP/1 Upgrade request flows
// through the abox MITM proxy, the upstream sends 101 Switching Protocols,
// the proxy correctly hijacks the connection, and bidirectional byte-streaming
// works post-upgrade.
//
// httputil.ReverseProxy detects Upgrade requests since Go 1.12 and switches to
// raw byte copy on a 101 response; this test exercises that path through our
// MITM intercept.
func TestProxy_WebSocket_Upgrade(t *testing.T) {
	// Upstream: a TLS server with an h1-only Upgrade handler.
	// It expects the client to send "ping\n" then it echoes "pong\n".
	upgradeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected Upgrade: websocket", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacker not supported", http.StatusInternalServerError)
			return
		}
		// Send 101 response, then hijack.
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read one line from the (pre-buffered) reader to get "ping".
		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		if line != "ping\n" {
			return
		}
		_, _ = conn.Write([]byte("pong\n"))
	})

	ts := httptest.NewUnstartedServer(upgradeHandler)
	// h1 only — h2 doesn't support Upgrade.
	ts.StartTLS()
	defer ts.Close()

	caPEM, _, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	// Use the testProxy helper's client (h1 only) to drive a CONNECT to the
	// upstream, then drop down to raw bytes for the Upgrade exchange.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	// Dial the proxy and do CONNECT manually.
	proxyConn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()
	tsHost := ts.Listener.Addr().String()
	connectReq := "CONNECT " + tsHost + " HTTP/1.1\r\nHost: " + tsHost + "\r\n\r\n"
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

	// Drain any buffered bytes from br into a new buffered TLS conn.
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"http/1.1"},
		ServerName: "127.0.0.1",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake to MITM cert: %v", err)
	}
	defer func() { _ = tlsConn.Close() }()

	// Send the Upgrade request.
	upgradeReq := "GET /ws HTTP/1.1\r\n" +
		"Host: " + tsHost + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := tlsConn.Write([]byte(upgradeReq)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	// Read the 101 response.
	tlsBR := bufio.NewReader(tlsConn)
	upgradeResp, err := http.ReadResponse(tlsBR, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if upgradeResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", upgradeResp.StatusCode)
	}

	// Post-upgrade exchange: write "ping\n", expect "pong\n".
	if _, err := tlsConn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	pong, err := tlsBR.ReadString('\n')
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if pong != "pong\n" {
		t.Errorf("got %q, want \"pong\\n\"", pong)
	}
}

// TestProxy_WebSocket_ShutdownDrainsActiveStream verifies that Shutdown closes
// a WebSocket session that's already been hijacked by ReverseProxy from the
// inner h1 server. This is the regression two peer reviewers flagged: with
// the original hijackWG design, intercept's WG.Done fired as soon as the inner
// server returned (which happens when ReverseProxy hijacks), so Shutdown
// thought the session was drained while the WS conn was still active.
func TestProxy_WebSocket_ShutdownDrainsActiveStream(t *testing.T) {
	// Upstream: holds the upgraded conn open until its read errors. We never
	// write back, so the only way for the client to unblock is for abox to
	// close the conn during Shutdown.
	upgradeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacker not supported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// Block reading; never write back. Closes when client/proxy closes.
		_, _ = io.Copy(io.Discard, conn)
	})

	ts := httptest.NewUnstartedServer(upgradeHandler)
	ts.StartTLS()
	defer ts.Close()

	caPEM, server, proxyURL, _ := testProxy(t, originCAPool(ts))
	// We intentionally drive Shutdown ourselves rather than via the helper's
	// cleanup, to time it.

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	proxyConn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()
	tsHost := ts.Listener.Addr().String()
	if _, err := io.WriteString(proxyConn,
		"CONNECT "+tsHost+" HTTP/1.1\r\nHost: "+tsHost+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(proxyConn)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: err=%v status=%v", err, resp)
	}
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}
	defer func() { _ = tlsConn.Close() }()
	if _, err := io.WriteString(tlsConn,
		"GET /ws HTTP/1.1\r\nHost: "+tsHost+"\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	tlsBR := bufio.NewReader(tlsConn)
	upResp, err := http.ReadResponse(tlsBR, nil)
	if err != nil || upResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: err=%v status=%v", err, upResp)
	}

	// WebSocket session is now active. The proxy has handed tlsConn off to
	// ReverseProxy's bidirectional copy. Before the fix, Shutdown would
	// return immediately leaving this conn alive.

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("Shutdown took %v, expected prompt drain", elapsed)
	}

	// Confirm the conn was actually closed by Shutdown: reading from it must
	// fail with EOF / use-of-closed in a bounded time.
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := tlsConn.Read(buf); err == nil {
		t.Error("client read succeeded; expected conn closed by Shutdown")
	}
}
