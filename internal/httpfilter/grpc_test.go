package httpfilter

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// connectDialer returns a context dialer that establishes a TCP connection
// through an HTTP CONNECT proxy. Used to drive gRPC traffic through the abox
// proxy (gRPC has no built-in HTTP_PROXY support).
func connectDialer(proxyAddr string) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 10 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		if _, err := io.WriteString(conn, req); err != nil {
			_ = conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
		}
		return conn, nil
	}
}

// TestProxy_gRPC_Roundtrip drives a real gRPC health-check call through the
// abox MITM proxy. Exercises trailers, h2 framing, and ALPN negotiation
// end-to-end — the same path dolt's gRPC traffic takes.
func TestProxy_gRPC_Roundtrip(t *testing.T) {
	// Build a separate CA + cert for the gRPC origin so we can install it as
	// a trusted root in the abox upstream transport AND in the gRPC client.
	originCertPEM, originKeyPEM, err := generateOriginCertForIP("127.0.0.1")
	if err != nil {
		t.Fatalf("origin cert: %v", err)
	}
	originCert, err := tls.X509KeyPair(originCertPEM, originKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	originPool := x509.NewCertPool()
	if !originPool.AppendCertsFromPEM(originCertPEM) {
		t.Fatalf("append origin CA")
	}

	// gRPC server with the health service.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = lis.Close() }()
	serverCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{originCert},
		NextProtos:   []string{"h2"},
	})
	grpcServer := grpc.NewServer(grpc.Creds(serverCreds))
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.GracefulStop()

	// abox proxy with MITM, trusting the origin's CA so the reverse-proxy can
	// dial it.
	aboxCAPEM, server, proxyURL, cleanup := testProxy(t, originPool)
	defer cleanup()

	// Surface upstream errors so failures are diagnosable.
	server.reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		t.Logf("upstream error: host=%s url=%s err=%v", r.Host, r.URL, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	// gRPC client that:
	//   - dials via the abox proxy using CONNECT,
	//   - performs its own TLS to the origin, trusting the origin's CA.
	//
	// Note: we trust the origin CA here, not the abox CA, because the gRPC
	// client speaks TLS end-to-end to the origin THROUGH the proxy's tunnel
	// after MITM completes. abox's MITM cert is presented to the client at
	// the inner h2 layer, so the gRPC client also needs to trust abox's CA.
	// Both go into one pool.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(aboxCAPEM)
	pool.AppendCertsFromPEM(originCertPEM)
	clientCreds := credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	})

	target := lis.Addr().String()
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithContextDialer(connectDialer(proxyURL.Host)),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := healthpb.NewHealthClient(conn)

	// Unary call: tests basic h2 + trailers (gRPC encodes status in trailers).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("status = %v, want SERVING", resp.GetStatus())
	}

	// Server-stream call: tests bidirectional h2 framing with multiple
	// DATA frames before the trailer.
	stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if msg.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("stream status = %v, want SERVING", msg.GetStatus())
	}
	// Stream cleanup happens via ctx cancel.
}

// generateOriginCertForIP returns a self-signed TLS cert/key for an IP host.
// Used by tests; not for production.
func generateOriginCertForIP(ip string) ([]byte, []byte, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, nil, errors.New("invalid IP")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ip},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{parsed},
		IsCA:                  true, // self-signed root for test
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
