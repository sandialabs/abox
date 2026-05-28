// HTTP/HTTPS forward + CONNECT-MITM proxy handler.
//
// This file owns proxy mechanics; policy lives in server.go (decideConnect,
// decideRequest, generateCertForHost, etc.). The handler reaches into
// *Server directly via method calls rather than callbacks because there is
// one consumer.

package httpfilter

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/sandialabs/abox/internal/logging"
)

// connectAction is the verdict for a CONNECT request.
type connectAction int

const (
	actionReject    connectAction = iota // reply 403, close
	actionTunnel                         // raw TCP tunnel, no MITM
	actionIntercept                      // hijack + TLS + h2/h1 dispatch
)

// requestDecision is the verdict for a fully-parsed inbound request (forward
// proxy or post-MITM, h1 or h2).
//
// forward=true means proxy the request upstream via reverseProxy.
// forward=false means synthesize the response from status+body — used for both
// blocks (4xx) and the healthcheck shortcut (200).
type requestDecision struct {
	forward bool
	status  int
	body    string
}

// handler is the proxy http.Handler. Internal to the package.
type handler struct {
	s *Server
}

func newProxyHandler(s *Server) http.Handler {
	return &handler{s: s}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodConnect:
		h.handleConnect(w, r)
	case r.URL.IsAbs():
		h.handleForward(w, r)
	default:
		http.Error(w, "abox http-filter: not a proxy request", http.StatusBadRequest)
	}
}

func (h *handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := extractHost(r.Host)
	switch h.s.decideConnect(host) {
	case actionReject:
		http.Error(w, "Access denied", http.StatusForbidden)
	case actionTunnel:
		h.tunnel(w, r)
	case actionIntercept:
		// Pass r.Host (with port) so the requestHandler can preserve the
		// upstream port — h2 servers strip the port from :authority before
		// dispatching to the handler.
		h.intercept(w, r, r.Host)
	}
}

// intercept hijacks the CONNECT conn, completes TLS with ALPN dispatch, then
// serves h2 or h1 requests through requestHandler.
//
// connectTarget is the original CONNECT target as "host:port". The conn is
// wrapped in a trackedConn so the abox Shutdown path can drain in-flight MITM
// sessions including streams that ReverseProxy hijacks (e.g. WebSocket) and
// continues using after this function returns.
func (h *handler) intercept(w http.ResponseWriter, r *http.Request, connectTarget string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	rawConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	// Clear any deadline the outer http.Server set on the conn before Hijack.
	// Its WriteTimeout=30s would otherwise terminate long-lived MITM streams
	// (WebSockets, SSE, gRPC, large downloads) after 30s.
	_ = rawConn.SetDeadline(time.Time{})

	if _, err := rawConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		_ = rawConn.Close()
		return
	}

	tlsCfg, err := h.s.generateCertForHost(extractHost(connectTarget))
	if err != nil {
		_ = rawConn.Close()
		return
	}
	// Clone before mutating NextProtos so the per-call config doesn't leak
	// state through the cached cert sharing.
	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	// Wrap the conn so any Close (inner server, ReverseProxy hijack handoff,
	// our shutdown watcher) deregisters from s.activeConns exactly once. This
	// is what makes Shutdown able to drain MITM sessions whose lifetime
	// outlives intercept's stack frame.
	conn := h.s.trackConn(rawConn)

	// Watcher: close the conn when Shutdown is called. Exit when the conn
	// closes by any other path, so we don't leak one goroutine per MITM
	// session over the server's lifetime.
	go func() {
		select {
		case <-h.s.hijackCtx.Done():
			_ = conn.Close()
		case <-conn.closed:
		}
	}()

	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(h.s.hijackCtx); err != nil {
		_ = conn.Close()
		return
	}

	inner := h.requestHandler(connectTarget)
	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case "h2":
		// http1Server is shared as BaseConfig — http2.Server reads timeouts
		// and limits from it without mutating.
		h.s.http2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
			Context:    h.s.hijackCtx,
			Handler:    inner,
			BaseConfig: h.s.http1Server,
		})
	default:
		// Fresh per-call http.Server because http.Server contains atomic state
		// that must not be copied. Mirror ReadHeaderTimeout/IdleTimeout but
		// NOT WriteTimeout — that would kill long-lived MITM connections
		// (WebSockets, SSE, large downloads).
		l := newOneShotListener(tlsConn)
		srv := &http.Server{
			ReadHeaderTimeout: h.s.http1Server.ReadHeaderTimeout,
			IdleTimeout:       h.s.http1Server.IdleTimeout,
			Handler:           inner,
			BaseContext:       func(net.Listener) context.Context { return h.s.hijackCtx },
			// Close the listener when our one conn finishes so srv.Serve's
			// next Accept returns and Serve exits. Without this, Serve loops
			// on Accept forever after the conn closes.
			ConnState: func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed || state == http.StateHijacked {
					_ = l.Close()
				}
			},
		}
		_ = srv.Serve(l)
	}
}

// handleForward serves a forward-proxy request (GET http://example.com/...).
// No CONNECT context, so connectTarget is "".
func (h *handler) handleForward(w http.ResponseWriter, r *http.Request) {
	h.requestHandler("").ServeHTTP(w, r)
}

// requestHandler returns the per-request http.Handler shared by the forward
// path and the post-MITM (h1 and h2) paths.
//
// connectTarget is the CONNECT target as "host:port" for MITM'd requests, or
// "" for forward-proxy requests. For MITM'd requests we route upstream to the
// CONNECT target's host:port (h2 servers strip the port from :authority, so
// r.Host alone is insufficient to dial). The inbound r.Host is still
// available to decideRequest for domain-fronting detection.
func (h *handler) requestHandler(connectTarget string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || r.URL == nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Stdlib servers leave URL.Scheme/Host empty on server-received
		// requests; the reverse proxy needs them populated.
		if r.URL.Scheme == "" {
			if connectTarget != "" {
				r.URL.Scheme = "https"
			} else {
				r.URL.Scheme = "http"
			}
		}
		if connectTarget != "" {
			r.URL.Host = connectTarget
		} else if r.URL.Host == "" {
			r.URL.Host = r.Host
		}

		d := h.s.decideRequest(r, connectTarget)
		if !d.forward {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(d.status)
			_, _ = io.WriteString(w, d.body)
			return
		}
		h.s.reverseProxy.ServeHTTP(w, r)
	})
}

// tunnel implements a non-MITM CONNECT: hijack the client conn, dial the
// upstream, copy bytes in both directions until either side closes.
//
// Like intercept, the conn is wrapped via trackConn so Shutdown can drain
// in-flight tunnels. The outer server's WriteTimeout is cleared after Hijack
// for the same reason as intercept.
func (h *handler) tunnel(w http.ResponseWriter, r *http.Request) {
	upstream, err := net.DialTimeout("tcp", r.Host, 30*time.Second)
	if err != nil {
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	rawConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = rawConn.SetDeadline(time.Time{})

	if _, err := rawConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		_ = rawConn.Close()
		return
	}

	conn := h.s.trackConn(rawConn)
	defer conn.Close()

	// Watcher closes the client conn on Shutdown so the io.Copy from upstream
	// errors out and the function returns. The watcher itself exits when conn
	// closes by any path.
	go func() {
		select {
		case <-h.s.hijackCtx.Done():
			_ = conn.Close()
		case <-conn.closed:
		}
	}()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

// newReverseProxy constructs the upstream-forwarding ReverseProxy used by all
// allowed requests (forward and post-MITM). The Transport is shared so
// connections pool across requests.
func newReverseProxy(transport *http.Transport) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(_ *httputil.ProxyRequest) {
			// Out is cloned from In before Rewrite runs, with Scheme/Host
			// populated by our requestHandler and RawQuery already sanitized
			// by stdlib's cleanQueryParams. No further changes needed.
			// (Aliasing Out.URL to In.URL would undo the query sanitization.)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logging.Debug("http upstream error",
				"host", r.Host,
				"url", urlString(r),
				"err", err,
			)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
		},
	}
}

// trackedConn wraps a net.Conn so abox's Shutdown path can drain MITM and
// tunnel sessions whose lifetime outlives intercept's stack frame (notably:
// WebSocket and other Upgrade streams that ReverseProxy hijacks from the
// inner h1 server).
//
// The first Close decrements activeConns and signals .closed exactly once;
// subsequent Closes are no-ops returning nil. The wrapper is composed via
// embedding so all other net.Conn methods (Read, Write, deadlines, addresses)
// pass through unchanged.
type trackedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
	closed  chan struct{}
}

func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		close(c.closed)
		c.onClose()
	})
	return err
}

// oneShotListener implements net.Listener, returning a single net.Conn on the
// first Accept call and blocking subsequent calls until Close. http.Server.Serve
// requires a listener; this lets us serve HTTP/1.1 on a single hijacked conn.
type oneShotListener struct {
	conn      net.Conn
	acceptOne sync.Once
	closeOne  sync.Once
	done      chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	return &oneShotListener{conn: c, done: make(chan struct{})}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.acceptOne.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

// Close is safe to call multiple times and from multiple goroutines —
// http.Server.Shutdown can race with our own teardown path.
func (l *oneShotListener) Close() error {
	l.acceptOne.Do(func() {}) // ensure subsequent Accept calls see done, not the conn
	l.closeOne.Do(func() { close(l.done) })
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
