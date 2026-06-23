// Upstream-proxy chaining for the non-MITM CONNECT tunnel path.
//
// The transport path (forward + post-MITM requests) gets upstream-proxy
// support from http.Transport.Proxy; this file provides the equivalent for
// tunnel(), which works at the raw-conn level: when proxyForURL selects an
// upstream proxy for the CONNECT target, we dial the proxy and chain a
// CONNECT through it instead of dialing the target directly.

package httpfilter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

const (
	schemeSOCKS5  = "socks5"
	schemeSOCKS5H = "socks5h"
)

// connectExchangeTimeout bounds the CONNECT request/response exchange with an
// upstream proxy. Matches the dial timeout used throughout this package.
const connectExchangeTimeout = 30 * time.Second

// maxProxyResponseHeader bounds the upstream proxy's CONNECT response headers
// (a conservative bound; stdlib Transport allows up to 10 MiB), so a broken or
// hostile proxy can't feed unbounded data before the tunnel is established.
const maxProxyResponseHeader = 1 << 20

// dialUpstreamTunnel opens a TCP conn to target ("host:port"), either directly
// or — when proxyForURL selects an upstream proxy for https://target — through
// that proxy (chained CONNECT for http/https proxies, SOCKS5 otherwise).
// CONNECT targets carry https semantics (https_proxy governs), matching
// goproxy's old env-based ConnectDial.
func (s *Server) dialUpstreamTunnel(ctx context.Context, target string) (net.Conn, error) {
	proxyURL, err := s.proxyForURL(&url.URL{Scheme: schemeHTTPS, Host: target})
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	if proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", target)
	}
	// Same scheme set the transport path supports (http.Transport.Proxy).
	switch proxyURL.Scheme {
	case schemeHTTP, schemeHTTPS:
		return dialViaConnect(ctx, dialer, proxyURL, target)
	case schemeSOCKS5, schemeSOCKS5H:
		return dialViaSOCKS5(ctx, dialer, proxyURL, target)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}

// proxyAddr returns the dialable "host:port" for a proxy URL, defaulting the
// port from the scheme. Built from Hostname/Port (not URL.Host) so IPv6
// literal proxies re-bracket correctly.
func proxyAddr(proxyURL *url.URL) string {
	port := proxyURL.Port()
	if port == "" {
		switch proxyURL.Scheme {
		case schemeHTTPS:
			port = "443"
		case schemeSOCKS5, schemeSOCKS5H:
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(proxyURL.Hostname(), port)
}

// dialViaConnect dials proxyURL, sends "CONNECT target" (with basic
// Proxy-Authorization when proxyURL has userinfo), validates the 200 response,
// and returns a conn positioned at the start of the tunnel byte stream.
func dialViaConnect(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, target string) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr(proxyURL))
	if err != nil {
		return nil, err
	}

	// Bound everything up to the established tunnel — the TLS handshake to an
	// https proxy AND the CONNECT exchange — with a deadline, and force it to
	// fail fast if ctx is canceled mid-flight (Shutdown cancels hijackCtx);
	// the deadline alone would hold the CONNECT handler for up to 30s.
	// The poke goes through `raw`, never reassigned: the AfterFunc closure
	// runs on its own goroutine, so poking `conn` (reassigned to the tls.Conn
	// below) would race that write. Deadlines on the raw conn pass through
	// tls.Conn, so targeting raw is equivalent.
	raw := conn
	_ = raw.SetDeadline(time.Now().Add(connectExchangeTimeout))
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if proxyURL.Scheme == schemeHTTPS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: proxyURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u := proxyURL.User; u != nil {
		pass, _ := u.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + pass))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}

	br := bufio.NewReader(io.LimitReader(conn, maxProxyResponseHeader))
	// resp.Body is deliberately never read or closed: CONNECT is not in
	// stdlib's noResponseBodyExpected set, so a 200 without Content-Length
	// gets a read-until-EOF body whose Close would drain live tunnel bytes.
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect}) //nolint:bodyclose // see comment above
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT refused: %s", resp.Status)
	}

	// Stop the cancellation poke BEFORE clearing the deadline. The reverse
	// order would let a ctx cancellation land between the clear and the stop,
	// poisoning a conn we are about to return as live with a past deadline.
	// stop()==false means the poke fired (ctx is done): the tunnel is being
	// torn down, so fail rather than return a poisoned conn.
	if !stop() {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = raw.SetDeadline(time.Time{})

	// The reader may have buffered tunnel bytes past the response headers
	// (server-speaks-first protocols, or a proxy that coalesces writes).
	// Stdlib can discard its reader because the transport always speaks TLS
	// next; a raw tunnel cannot.
	if n := br.Buffered(); n > 0 {
		peeked, err := br.Peek(n)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy CONNECT buffered bytes: %w", err)
		}
		// Copy: the peeked slice aliases the bufio buffer.
		buffered := append([]byte(nil), peeked...)
		return &prefixConn{
			Conn: conn,
			r:    io.MultiReader(bytes.NewReader(buffered), conn),
		}, nil
	}
	return conn, nil
}

// dialViaSOCKS5 dials target through a SOCKS5 proxy, with username/password
// auth when proxyURL has userinfo. The target hostname is sent to the proxy
// for resolution (socks5h semantics) for both schemes, matching
// net/http.Transport's treatment of socks5 proxy URLs.
func dialViaSOCKS5(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, target string) (net.Conn, error) {
	var auth *proxy.Auth
	if u := proxyURL.User; u != nil {
		pass, _ := u.Password()
		auth = &proxy.Auth{User: u.Username(), Password: pass}
	}
	fwd := &socksForwardDialer{d: dialer}
	d, err := proxy.SOCKS5("tcp", proxyAddr(proxyURL), auth, fwd)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy: %w", err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		// proxy.SOCKS5 always returns a ContextDialer today; defensive so a
		// future x/net change degrades loudly instead of hanging Shutdown.
		return nil, errors.New("socks5 dialer does not support context cancellation")
	}
	// The socks client derives its handshake I/O deadline from ctx.Deadline()
	// (and watches ctx.Done() for cancellation); ctx here is hijackCtx, which
	// has no deadline, so bound the handshake explicitly — same rationale as
	// the CONNECT exchange deadline in dialViaConnect.
	dialCtx, cancel := context.WithTimeout(ctx, connectExchangeTimeout)
	defer cancel()
	conn, err := cd.DialContext(dialCtx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial: %w", err)
	}
	// x/net's socks conn embeds the net.Conn interface, so the TCP conn's
	// CloseWrite is not promoted and the tunnel splice's halfCloser assertion
	// would fail — half-close would silently stop propagating through socks5
	// tunnels. Restore it via the raw conn the forward dialer recorded.
	return &socksConn{Conn: conn, raw: fwd.raw}, nil
}

// socksForwardDialer is the forward dialer handed to proxy.SOCKS5. It records
// the raw TCP conn it dials so dialViaSOCKS5 can restore CloseWrite on the
// returned socks conn. Single-use: one dial per dialViaSOCKS5 call, and the
// socks handshake completes before DialContext returns, so `raw` is never
// accessed concurrently.
type socksForwardDialer struct {
	d   *net.Dialer
	raw net.Conn
}

func (f *socksForwardDialer) Dial(network, addr string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, addr)
}

func (f *socksForwardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := f.d.DialContext(ctx, network, addr)
	f.raw = conn
	return conn, err
}

// socksConn is a net.Conn that restores the write-side half-close hidden by
// x/net's socks conn, delegating CloseWrite to the raw conn beneath it (like
// trackedConn/limitedConn/prefixConn) so the tunnel's half-close survives.
type socksConn struct {
	net.Conn          // the socks conn: Read/Write/Close
	raw      net.Conn // the TCP conn beneath it
}

func (c *socksConn) CloseWrite() error {
	if cw, ok := c.raw.(halfCloser); ok {
		return cw.CloseWrite()
	}
	return nil
}

// prefixConn is a net.Conn whose Read first drains bytes buffered during the
// CONNECT response parse, then continues from the conn. CloseWrite is
// delegated (like trackedConn/limitedConn) so the tunnel's half-close
// survives the wrapper.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(halfCloser); ok {
		return cw.CloseWrite()
	}
	return nil
}
