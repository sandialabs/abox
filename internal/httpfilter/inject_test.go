package httpfilter

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/cert"
	"github.com/sandialabs/abox/internal/logging"
)

// echoOrigin is an HTTPS test origin (h1) that reflects the named request header
// value in its body, so tests can observe exactly what the proxy forwarded
// upstream.
func echoOrigin(t *testing.T, header string) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get(header))
	}))
	t.Cleanup(ts.Close)
	return ts
}

// getViaMITM issues an HTTPS GET through the abox MITM proxy and returns the
// response body (the echoed header value). If setHeader[0] != "" the client sets
// that header itself (to test override/strip).
func getViaMITM(t *testing.T, caPEM []byte, proxyURL *url.URL, target string, setHeader [2]string) string {
	t.Helper()
	client := clientTrustingAboxCA(t, caPEM, proxyURL, false)
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if setHeader[0] != "" {
		req.Header.Set(setHeader[0], setHeader[1])
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// testProxyNoLoopback is like testProxy but does NOT opt loopback into the SSRF
// policy, so the dial-time gate blocks connections to the loopback test origin.
func testProxyNoLoopback(t *testing.T, upstreamCA *x509.CertPool) (caPEM []byte, server *Server, proxyURL *url.URL, cleanup func()) {
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

func TestInject_HeaderAddedToUpstream(t *testing.T) {
	ts := echoOrigin(t, "X-Api-Key")
	caPEM, server, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "127.0.0.1", Header: "X-Api-Key", Value: "sekret"},
	})

	if got := getViaMITM(t, caPEM, proxyURL, ts.URL+"/path", [2]string{}); got != "sekret" {
		t.Errorf("upstream saw X-Api-Key=%q, want %q", got, "sekret")
	}
}

func TestInject_OverridesClientSuppliedHeader(t *testing.T) {
	ts := echoOrigin(t, "X-Api-Key")
	caPEM, server, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "127.0.0.1", Header: "X-Api-Key", Value: "real"},
	})

	if got := getViaMITM(t, caPEM, proxyURL, ts.URL+"/path", [2]string{"X-Api-Key", "attacker"}); got != "real" {
		t.Errorf("upstream saw X-Api-Key=%q, want %q (client value must be overridden)", got, "real")
	}
}

func TestInject_ValuePrefixApplied(t *testing.T) {
	ts := echoOrigin(t, "Authorization")
	caPEM, server, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	// serve.go resolves value_prefix into Value; simulate a "Bearer " prefix here.
	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "127.0.0.1", Header: "Authorization", Value: "Bearer tok"},
	})

	if got := getViaMITM(t, caPEM, proxyURL, ts.URL+"/x", [2]string{}); got != "Bearer tok" {
		t.Errorf("Authorization=%q, want %q", got, "Bearer tok")
	}
}

func TestInject_NonBoundHostUntouched(t *testing.T) {
	ts := echoOrigin(t, "X-Api-Key")
	caPEM, server, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "api.other.example", Header: "X-Api-Key", Value: "sekret"},
	})

	if got := getViaMITM(t, caPEM, proxyURL, ts.URL+"/path", [2]string{}); got != "" {
		t.Errorf("non-bound host should not be injected, upstream saw %q", got)
	}
}

func TestInject_PlaintextHTTPNotInjected(t *testing.T) {
	// Plain-HTTP forward proxy: isMITM is false, so no injection even for a bound
	// host — a secret must never go out over cleartext.
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Api-Key")
	}))
	defer ts.Close()
	tsHost := strings.TrimPrefix(ts.URL, "http://")

	_, server, proxyURL, cleanup := testProxy(t, nil)
	defer cleanup()
	server.filter.Add(tsHost)
	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "127.0.0.1", Header: "X-Api-Key", Value: "sekret"},
	})

	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://" + tsHost + "/foo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if got != "" {
		t.Errorf("plaintext HTTP must not be injected, upstream saw %q", got)
	}
}

func TestInject_PathPrefixGate(t *testing.T) {
	ts := echoOrigin(t, "X-Api-Key")
	caPEM, server, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "127.0.0.1", Header: "X-Api-Key", Value: "sekret", PathPrefix: "/v1/"},
	})

	if got := getViaMITM(t, caPEM, proxyURL, ts.URL+"/v1/models", [2]string{}); got != "sekret" {
		t.Errorf("matching path: X-Api-Key=%q, want %q", got, "sekret")
	}
	if got := getViaMITM(t, caPEM, proxyURL, ts.URL+"/other", [2]string{}); got != "" {
		t.Errorf("non-matching path must not inject, saw %q", got)
	}
}

func TestInject_StripHeaderOnMissingValue(t *testing.T) {
	ts := echoOrigin(t, "X-Api-Key")
	caPEM, server, proxyURL, cleanup := testProxy(t, originCAPool(ts))
	defer cleanup()

	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "127.0.0.1", Header: "X-Api-Key", Strip: true},
	})

	if got := getViaMITM(t, caPEM, proxyURL, ts.URL+"/path", [2]string{"X-Api-Key", "attacker"}); got != "" {
		t.Errorf("strip rule must remove header, upstream saw %q", got)
	}
}

func TestInject_SSRFBlockPreventsTransmission(t *testing.T) {
	ts := echoOrigin(t, "X-Api-Key")
	caPEM, server, proxyURL, cleanup := testProxyNoLoopback(t, originCAPool(ts))
	defer cleanup()
	server.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "127.0.0.1", Header: "X-Api-Key", Value: "sekret"},
	})

	client := clientTrustingAboxCA(t, caPEM, proxyURL, false)
	if _, err := client.Get(ts.URL + "/path"); err == nil {
		t.Fatal("expected SSRF dial block, got nil error")
	}
}

func TestInject_AuditRecordsKeyAndHostNotValue(t *testing.T) {
	var buf bytes.Buffer
	restore := logging.SetAuditOutputForTest(&buf)
	defer restore()

	_, server, _, cleanup := testProxy(t, nil)
	defer cleanup()

	server.SetSecretInjections("box9", []SecretRule{
		{Key: "anthropic", Host: "api.anthropic.com", Header: "x-api-key", Value: "sk-secret-value"},
	})

	out := buf.String()
	if !strings.Contains(out, "action="+logging.ActionSecretInject) {
		t.Errorf("missing secret.inject audit: %q", out)
	}
	for _, want := range []string{"instance=box9", "filter=http", "host=api.anthropic.com", "key=anthropic"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit missing %q; got %q", want, out)
		}
	}
	if strings.Contains(out, "sk-secret-value") {
		t.Errorf("audit must NOT contain the secret value; got %q", out)
	}
}

// Unit tests for the path defenses that are awkward to drive through a real client
// (encoded separators get normalized or rejected by the client transport).

func TestSafeCleanPath(t *testing.T) {
	cases := []struct {
		rawPath  string // url.URL.RawPath (non-empty => non-canonical encoding)
		path     string // url.URL.Path (decoded)
		wantOK   bool
		wantPath string
	}{
		{"", "/v1/models", true, "/v1/models"},
		{"", "/v1/../debug", true, "/debug"},            // traversal collapsed away from /v1
		{"/v1%2f..%2fdebug", "/v1/../debug", false, ""}, // encoded separators rejected
		{"", "", true, "/"},                             // empty path -> root
		{"", "/a//b", true, "/a/b"},                     // doubled slash collapsed
	}
	for _, c := range cases {
		u := &url.URL{Path: c.path, RawPath: c.rawPath}
		got, ok := safeCleanPath(u)
		if ok != c.wantOK || (ok && got != c.wantPath) {
			t.Errorf("safeCleanPath(RawPath=%q, Path=%q) = (%q,%v), want (%q,%v)",
				c.rawPath, c.path, got, ok, c.wantPath, c.wantOK)
		}
	}
}

func TestMatchPrefix(t *testing.T) {
	cases := []struct {
		clean, prefix string
		want          bool
	}{
		{"/v1/models", "/v1/", true},
		{"/v1", "/v1/", true},
		{"/v10/models", "/v1/", false}, // must not match across a segment boundary
		{"/v1/models", "/v1", true},
		{"/v10", "/v1", false},
		{"/anything", "/", true},
	}
	for _, c := range cases {
		if got := matchPrefix(c.clean, c.prefix); got != c.want {
			t.Errorf("matchPrefix(%q, %q) = %v, want %v", c.clean, c.prefix, got, c.want)
		}
	}
}

// TestInject_StripFailsClosedOnEncodedPath drives injectSecrets directly with an
// outbound request whose path carries percent-encoded separators (RawPath set),
// which safeCleanPath refuses to normalize. A strip rule must STILL remove the
// guest-supplied header — the un-normalizable path must not become a bypass.
func TestInject_StripFailsClosedOnEncodedPath(t *testing.T) {
	s := NewServer(allowlist.NewFilter(), false)
	s.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "api.example.com", Header: "X-Api-Key", Strip: true},
	})

	out := &http.Request{
		URL:    &url.URL{Scheme: "https", Host: "api.example.com:443", Path: "/v1/../secret", RawPath: "/v1%2f..%2fsecret"},
		Header: http.Header{"X-Api-Key": []string{"attacker"}},
	}
	in := (&http.Request{}).WithContext(withMITM(context.Background()))
	s.injectSecrets(&httputil.ProxyRequest{In: in, Out: out})

	if got := out.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("strip must fail closed on an encoded path; header still present: %q", got)
	}
}

// TestInject_InjectSkippedOnEncodedPath is the companion: an inject rule must NOT
// fire on an un-normalizable path (fail safe — no secret over a suspicious path).
func TestInject_InjectSkippedOnEncodedPath(t *testing.T) {
	s := NewServer(allowlist.NewFilter(), false)
	s.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "api.example.com", Header: "X-Api-Key", Value: "sekret"},
	})

	out := &http.Request{
		URL:    &url.URL{Scheme: "https", Host: "api.example.com:443", Path: "/v1/x", RawPath: "/v1%2fx"},
		Header: http.Header{},
	}
	in := (&http.Request{}).WithContext(withMITM(context.Background()))
	s.injectSecrets(&httputil.ProxyRequest{In: in, Out: out})

	if got := out.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("inject must be skipped on an encoded path, got %q", got)
	}
}

// TestInject_KeysOnPinnedHostNotInnerHost locks the core security invariant: the
// injection host is the CONNECT-pinned pr.Out.URL.Host (set by requestHandler),
// never the guest-controlled inner Host (pr.In.Host). A guest that CONNECTs to a
// bound host still gets the secret (keyed on Out.URL.Host), and a guest that
// CONNECTs to an unbound host cannot redirect a bound secret via inner Host.
func TestInject_KeysOnPinnedHostNotInnerHost(t *testing.T) {
	s := NewServer(allowlist.NewFilter(), false)
	s.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "api.example.com", Header: "X-Api-Key", Value: "sekret"},
	})

	// Pinned (Out) host is the bound host; inner (In) Host is attacker-chosen.
	out := &http.Request{URL: &url.URL{Scheme: "https", Host: "api.example.com:443", Path: "/"}, Header: http.Header{}}
	in := (&http.Request{Host: "evil.example.com"}).WithContext(withMITM(context.Background()))
	s.injectSecrets(&httputil.ProxyRequest{In: in, Out: out})
	if out.Header.Get("X-Api-Key") != "sekret" {
		t.Errorf("secret must be injected based on pinned Out host; got %q", out.Header.Get("X-Api-Key"))
	}

	// Pinned host is unbound; inner Host claims the bound host — must NOT inject.
	out2 := &http.Request{URL: &url.URL{Scheme: "https", Host: "evil.example.com:443", Path: "/"}, Header: http.Header{}}
	in2 := (&http.Request{Host: "api.example.com"}).WithContext(withMITM(context.Background()))
	s.injectSecrets(&httputil.ProxyRequest{In: in2, Out: out2})
	if got := out2.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("inner Host must not redirect the secret to an unbound pinned host; got %q", got)
	}
}

// TestInject_NotInPassiveMode locks the fail-closed guarantee against a runtime
// active->passive toggle: no injection while profiling.
func TestInject_NotInPassiveMode(t *testing.T) {
	s := NewServer(allowlist.NewFilter(), true) // passive
	s.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "api.example.com", Header: "X-Api-Key", Value: "sekret"},
	})
	out := &http.Request{URL: &url.URL{Scheme: "https", Host: "api.example.com:443", Path: "/"}, Header: http.Header{}}
	in := (&http.Request{}).WithContext(withMITM(context.Background()))
	s.injectSecrets(&httputil.ProxyRequest{In: in, Out: out})
	if got := out.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("passive mode must not inject; got %q", got)
	}
}

// TestInject_NotOnTRACE locks that a TRACE request (which echoes the request back)
// never carries the injected secret.
func TestInject_NotOnTRACE(t *testing.T) {
	s := NewServer(allowlist.NewFilter(), false)
	s.SetSecretInjections("box", []SecretRule{
		{Key: "k", Host: "api.example.com", Header: "X-Api-Key", Value: "sekret"},
	})
	// Also assert the guest's own header is REMOVED on TRACE, so it can't smuggle
	// its own credential to the bound host on a request whose response echoes it.
	out := &http.Request{Method: http.MethodTrace, URL: &url.URL{Scheme: "https", Host: "api.example.com:443", Path: "/"}, Header: http.Header{"X-Api-Key": []string{"attacker"}}}
	in := (&http.Request{}).WithContext(withMITM(context.Background()))
	s.injectSecrets(&httputil.ProxyRequest{In: in, Out: out})
	if got := out.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("TRACE must carry no injected or guest-supplied credential; got %q", got)
	}
}

// TestUpstreamTransportHasNoKeyLog locks the invariant that the proxy->upstream
// transport never carries a TLS KeyLogWriter — otherwise a keylog+pcap of the
// upstream leg would expose the injected secret. Keylog is only for the
// guest-facing MITM configs.
func TestUpstreamTransportHasNoKeyLog(t *testing.T) {
	s := NewServer(allowlist.NewFilter(), false)
	if s.transport.TLSClientConfig != nil && s.transport.TLSClientConfig.KeyLogWriter != nil {
		t.Error("upstream transport must not have a KeyLogWriter (would expose injected secrets in a pcap)")
	}
}

func TestCanonicalHostMatchesExtractHost(t *testing.T) {
	// The binding side and the request side must produce the same key.
	cases := []struct{ binding, requestHostPort string }{
		{"API.Anthropic.COM", "api.anthropic.com:443"},
		{"api.anthropic.com.", "api.anthropic.com:443"},
		{"127.0.0.1", "127.0.0.1:8443"},
	}
	for _, c := range cases {
		a := canonicalHost(c.binding)
		b := canonicalHost(extractHost(c.requestHostPort))
		if a != b {
			t.Errorf("canonicalHost(%q)=%q != canonicalHost(extractHost(%q))=%q", c.binding, a, c.requestHostPort, b)
		}
	}
}
