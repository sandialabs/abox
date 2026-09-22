//go:build e2e

package e2e

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFilteredNetworkAllowsProxy tests that the network allows traffic through the proxy.
// Note: Security mode is always "filtered" - no open/closed modes exist.
func TestFilteredNetworkAllowsProxy(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Add a domain to the allowlist
	inst.allowlistAdd("example.com")

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try to make an HTTP request via proxy - should succeed.
	// Retry to allow time for proxy config to take effect in the VM.
	result := inst.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
		return r.Success()
	}, "curl", "-s", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "http://example.com")

	if !result.Success() {
		t.Errorf("HTTP request to allowed domain via proxy should succeed: %v", result.Stderr)
	}
}

// TestNetworkBlocksDirectAccess tests that direct network access is blocked.
// Traffic must go through the proxy in filtered mode.
func TestNetworkBlocksDirectAccess(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try to ping a public IP directly - should fail (nwfilter blocks direct access)
	result := inst.ssh("ping", "-c", "1", "-W", "5", "8.8.8.8")
	if result.Success() {
		t.Error("Direct ping to 8.8.8.8 succeeded - nwfilter should block direct access")
	}
}

// TestMITM_CACertGenerated tests that CA certificate is generated during instance creation.
func TestMITM_CACertGenerated(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()

	// Check that CA cert and key files were created
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home dir: %v", err)
	}

	instanceDir := filepath.Join(homeDir, ".local/share/abox/instances", inst.name)
	caCertPath := filepath.Join(instanceDir, "ca-cert.pem")
	caKeyPath := filepath.Join(instanceDir, "ca-key.pem")

	// Check CA cert exists
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Errorf("CA certificate not found at %s", caCertPath)
	}

	// Check CA key exists
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Errorf("CA key not found at %s", caKeyPath)
	}

	// Check CA key has restrictive permissions (0o600)
	info, err := os.Stat(caKeyPath)
	if err == nil {
		mode := info.Mode().Perm()
		if mode != 0o600 {
			t.Errorf("CA key should have 0o600 permissions, got %o", mode)
		}
	}

	// Verify CA cert contains expected content
	certData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	if !strings.Contains(string(certData), "BEGIN CERTIFICATE") {
		t.Error("CA cert file doesn't contain PEM certificate")
	}
}

// TestMITM_Enabled tests that MITM is enabled in the HTTP filter.
func TestMITM_Enabled(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	// Give HTTP filter time to start
	time.Sleep(5 * time.Second)

	// Check HTTP status - should show MITM is enabled
	result := env.run("http", "status", inst.name)
	if !result.Success() {
		t.Fatalf("HTTP status failed: %v", result.Err)
	}

	// Verify MITM is reported as enabled
	if !strings.Contains(strings.ToLower(result.Stdout), "mitm") {
		t.Errorf("HTTP status should mention MITM, got:\n%s", result.Stdout)
	}
}

// TestMITM_CATrustedInVM tests that the CA certificate is installed in the VM's trust store.
func TestMITM_CATrustedInVM(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Wait for cloud-init runcmd (runs update-ca-certificates).
	inst.waitForCloudInit()

	// Check that the CA certificate was installed by cloud-init
	// Try Debian path first, then RHEL path
	result := inst.ssh("cat", "/usr/local/share/ca-certificates/abox-proxy-ca.crt")
	if !result.Success() {
		// Try RHEL path
		result = inst.ssh("cat", "/etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt")
		if !result.Success() {
			t.Fatalf("CA cert not found in VM at either Debian or RHEL paths: %v", result.Stderr)
		}
	}

	if !strings.Contains(result.Stdout, "BEGIN CERTIFICATE") {
		t.Error("CA cert in VM doesn't contain PEM certificate")
	}

	// Verify it's in the system trust store (Debian path)
	result = inst.ssh("ls", "/etc/ssl/certs/abox-proxy-ca.pem")
	if !result.Success() {
		// Try RHEL - check if update-ca-trust was run successfully
		result = inst.ssh("trust", "list", "--filter=ca-anchors")
		if !result.Success() {
			t.Log("CA cert may not be in system trust store yet")
		}
	}
}

// TestMITM_HTTPSAllowedDomain tests that HTTPS to an allowed domain works through MITM.
func TestMITM_HTTPSAllowedDomain(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Wait for cloud-init runcmd (runs update-ca-certificates).
	inst.waitForCloudInit()

	// Add a domain to allowlist
	inst.allowlistAdd("example.com")

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try HTTPS request to allowed domain.
	// curl should succeed because:
	// 1. The domain is in allowlist (CONNECT allowed)
	// 2. MITM intercepts and re-encrypts (VM trusts our CA)
	// 3. Host header matches allowlist (no domain fronting)
	// Retry to allow time for cloud-init CA trust setup.
	result := inst.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
		return r.Success()
	}, "curl", "-s", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com")

	if !result.Success() {
		t.Errorf("HTTPS request to allowed domain should succeed through MITM proxy: %v", result.Stderr)
	}
}

// TestMITM_HTTP2AllowedDomain tests that an HTTP/2 request to an allowed domain
// works through the MITM proxy AND is actually served over h2. This exercises the
// h2 ServeConn intercept path (the headline feature of this branch) end-to-end in
// a real VM — the existing MITM e2e tests only drive HTTP/1.1. The client↔proxy
// hop negotiates h2 via ALPN against the MITM, so curl reports http_version 2
// regardless of the upstream's protocol; example.com keeps the host stable.
func TestMITM_HTTP2AllowedDomain(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Wait for cloud-init runcmd (update-ca-certificates) so the VM trusts our CA.
	inst.waitForCloudInit()

	inst.allowlistAdd("example.com")
	inst.setFilterMode("active")

	// curl --http2 forces HTTP/2 in the TLS ALPN. Report the negotiated version so
	// we can assert the MITM served h2, not just that the request succeeded. Retry
	// to allow CA-trust/proxy config to settle in the VM.
	result := inst.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
		return r.Success() && strings.TrimSpace(r.Stdout) == "2"
	}, "curl", "-s", "--http2", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_version}", "https://example.com")

	if !result.Success() {
		t.Fatalf("HTTP/2 request to allowed domain should succeed through MITM proxy: %v", result.Stderr)
	}
	if v := strings.TrimSpace(result.Stdout); v != "2" {
		t.Errorf("expected MITM to serve HTTP/2 (http_version=2), got %q — h2 ServeConn path not exercised", v)
	}
}

// TestMITM_HTTPSBlockedDomain tests that HTTPS to a non-allowed domain is blocked.
func TestMITM_HTTPSBlockedDomain(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Set filter to active mode
	inst.setFilterMode("active")

	// Try HTTPS request to a domain NOT in the default allowlist
	// The CONNECT request should be rejected by the proxy
	// Using a made-up domain that definitely isn't allowlisted
	result := inst.ssh("curl", "-s", "--max-time", "10", "https://this-domain-is-not-allowed.invalid")
	if result.Success() {
		t.Error("HTTPS request to non-allowed domain should have been blocked")
	}
}

// TestHTTPBlocksNonAllowlisted tests that HTTP requests to non-allowed domains get 403.
func TestHTTPBlocksNonAllowlisted(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Set filter to active mode
	inst.setFilterMode("active")

	// HTTP request to non-allowed domain should get 403 from the proxy
	result := inst.ssh("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "http://this-domain-is-not-allowed.invalid")
	if !result.Success() {
		t.Fatalf("curl command itself failed: %v", result.Stderr)
	}

	httpCode := strings.TrimSpace(result.Stdout)
	if httpCode != "403" {
		t.Errorf("HTTP request to non-allowed domain should return 403, got %s", httpCode)
	}
}

// TestDirectTCPToPublicIPDenied verifies that a direct TCP connection from the
// guest to a raw public IP (bypassing DNS/the proxy entirely) is denied. This
// complements TestNetworkBlocksDirectAccess (which only exercises ICMP) by
// exercising the TCP path against the nwfilter priority-999 default-deny. It is
// topology-independent by design: on the current NAT topology the nwfilter drops
// the packet, and after a host-only migration there is simply no route out, so
// the connection must fail in both worlds. We use curl (always present in the
// base image) to a well-known public resolver IP on 443; a successful egress
// would complete the TCP/TLS handshake and exit 0, so a non-zero exit proves the
// direct path is blocked. We additionally assert a raw TCP connect (no TLS, via
// the bash /dev/tcp probe) is refused, isolating the failure to the transport layer.
func TestDirectTCPToPublicIPDenied(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Set filter to active mode (mirrors the other isolation tests).
	inst.setFilterMode("active")

	// Direct HTTPS to a raw public IP must fail. --max-time bounds the drop-induced
	// hang so the test never blocks; a blocked connection exits non-zero (timeout).
	result := inst.ssh("curl", "-sS", "--max-time", "5", "https://1.1.1.1")
	if result.Success() {
		t.Errorf("direct TCP/TLS to raw public IP 1.1.1.1 succeeded - nwfilter/host-only "+
			"default-deny should block direct egress: %s", result.Stdout)
	}

	// Stronger, transport-only assertion: a raw TCP connect (no TLS) to 1.1.1.1:443
	// must not complete. Uses the bash /dev/tcp connect probe (bash is the login
	// shell on every base image) so this leg always runs rather than skipping.
	if tcp := inst.guestCanConnect("1.1.1.1", 443); tcp.Success() {
		t.Error("raw TCP connect to 1.1.1.1:443 succeeded - direct egress should be blocked")
	}
}

// TestPublicDNSResolverDenied verifies that the guest cannot use a public DNS
// resolver to bypass the local dnsfilter. There are two distinct properties, and
// the naive test (plain :53 to 8.8.8.8 must fail) is WRONG: the host DNS REDIRECT
// (internal/privilege/helper.go) is destination-agnostic (it matches --dport 53
// with no -d), so ANY :53 packet - even addressed to 8.8.8.8 - is transparently
// DNAT'd to the local dnsfilter and answered. A plain `nslookup foo 8.8.8.8`
// therefore SUCCEEDS. We instead assert the two real invariants:
//
//	(a) Non-53 bypass is denied: DNS on a non-53 port (5353) to 8.8.8.8 is not
//	    caught by the :53 REDIRECT and is dropped by the nwfilter's
//	    dstipaddr != gateway rule, so it must fail even for an allowlisted domain.
//	(b) Provenance: a query to 8.8.8.8:53 is actually captured by our dnsfilter,
//	    not answered by the real resolver. We prove this with a domain that is
//	    real+publicly-resolvable but NOT allowlisted (example.org): the real
//	    8.8.8.8 would resolve it, so a block/NXDOMAIN proves our filter answered.
//	    An allowlisted domain (example.com) at 8.8.8.8:53 is used as a positive
//	    control that also confirms nslookup itself is functional.
//
// Both properties are topology-independent: under host-only there is no route to
// 8.8.8.8 at all, so (a) still fails and (b)'s :53 path still terminates locally.
func TestPublicDNSResolverDenied(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// Both properties are asserted with nslookup because it is the only common
	// guest tool that can target a specific server AND a specific port. getent
	// cannot (it always uses the system resolver on :53). Skip cleanly if the
	// image lacks it so a missing tool never masquerades as "blocked".
	if !inst.guestHasCommand("nslookup") {
		t.Skip("nslookup (dnsutils) not present in guest; cannot target server/port")
	}

	// Allowlist example.com so it is a valid positive control; example.org is left
	// off the allowlist so our filter blocks it while the real 8.8.8.8 would not.
	inst.allowlistAdd("example.com")
	inst.setFilterMode("active")

	t.Run("provenance-allowlisted-domain-captured-at-8888", func(t *testing.T) {
		// Positive control: example.com at 8.8.8.8:53 is DNAT'd to our dnsfilter and,
		// being allowlisted, resolves. This also proves nslookup is functional. Retry
		// to let the allowlist reload propagate to the dnsfilter.
		result := inst.waitForSSHCondition(15*time.Second, 2*time.Second, dnsResolved,
			"nslookup", "example.com", "8.8.8.8")
		if !dnsResolved(result) {
			t.Errorf("allowlisted example.com via 8.8.8.8:53 should resolve (captured by "+
				"local dnsfilter): stdout=%q stderr=%q", result.Stdout, result.Stderr)
		}
	})

	t.Run("provenance-blocked-domain-blocked-at-8888", func(t *testing.T) {
		// Discriminating provenance proof: example.org is a real, publicly resolvable
		// domain that the true 8.8.8.8 WOULD answer, but it is not allowlisted. If the
		// query reached the real resolver it would resolve; the fact that it is blocked
		// proves the :53 REDIRECT captured it locally and our dnsfilter answered.
		result := inst.ssh("nslookup", "example.org", "8.8.8.8")
		if dnsResolved(result) {
			t.Errorf("non-allowlisted example.org via 8.8.8.8:53 resolved - query was NOT "+
				"captured by the local dnsfilter (answered by the real resolver): stdout=%q",
				result.Stdout)
		}
	})

	t.Run("non-53-port-bypass-denied", func(t *testing.T) {
		// The :53 REDIRECT does not catch a non-53 destination port, so DNS to
		// 8.8.8.8:5353 is left to the nwfilter, which drops dstipaddr != gateway.
		// Query the ALLOWLISTED domain so the ONLY reason it can fail is the transport
		// being blocked (not domain policy): if the non-53 path were open it would
		// reach the real 8.8.8.8 and resolve example.com.
		result := inst.ssh("nslookup", "-port=5353", "example.com", "8.8.8.8")
		if dnsResolved(result) {
			t.Errorf("DNS to 8.8.8.8:5353 resolved - non-53 egress should be denied "+
				"(REDIRECT only catches :53; nwfilter drops non-gateway dst): stdout=%q",
				result.Stdout)
		}
	})
}

// TestGuestToHostNonFilterPortIsolation verifies the guest→host boundary: the
// guest may reach ONLY the DNS/HTTP filter ports on the gateway, and nothing
// else. The negative half is the load-bearing part, so it must not pass for the
// wrong reason: rather than probing a port with nothing listening (where a policy
// DROP is indistinguishable from "nobody home"), the HOST binds a real TCP
// listener on the gateway IP on an ephemeral non-filter port, then asserts the
// guest still cannot connect to it. That proves the host IS listening but the
// guest is dropped by the host guest→host default-deny (the INPUT dedicated
// chain today; the FORWARD deny too under host-only). The positive half asserts
// the guest CAN reach the httpfilter listener (its only sanctioned host port).
// Both probes use the bash /dev/tcp connect helper (bash is the login shell on
// every base image, unlike python3 which is absent on almalinux-8), which cleanly
// distinguishes an established handshake from a drop/timeout. Topology-independent:
// the bound non-filter port is denied and the filter port reachable under host-only.
func TestGuestToHostNonFilterPortIsolation(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	inst.setFilterMode("active")

	gateway, _, httpPort := inst.gatewayAndPorts()
	if gateway == "" || httpPort == 0 {
		t.Fatalf("could not determine gateway/httpPort (gateway=%q httpPort=%d)", gateway, httpPort)
	}

	// Positive: the httpfilter port on the gateway must be reachable (the guest's
	// only sanctioned egress path). Retry to allow the filter to finish binding.
	reachable := inst.waitForSSHCondition(20*time.Second, 2*time.Second, func(r *runResult) bool {
		return r.Success()
	}, tcpConnectCmd(gateway, httpPort))
	if !reachable.Success() {
		t.Errorf("httpfilter port %s:%d should be reachable from the guest: %s",
			gateway, httpPort, reachable.Stderr)
	}

	// Negative: bind a REAL host listener on the gateway IP on an ephemeral,
	// non-filter port. Because the socket is actively listening, a guest connect
	// would complete IF policy allowed it — so a failed connect proves the host
	// guest→host default-deny dropped the packet, not that the port was closed.
	// The kernel picks the port via ":0"; it cannot collide with the already-bound
	// dns/http filter ports (those sockets are in use).
	l, err := net.Listen("tcp", net.JoinHostPort(gateway, "0"))
	if err != nil {
		t.Fatalf("failed to bind host listener on gateway %s: %v", gateway, err)
	}
	defer l.Close()
	listenPort := l.Addr().(*net.TCPAddr).Port

	if blocked := inst.guestCanConnect(gateway, listenPort); blocked.Success() {
		t.Errorf("guest reached non-filter host port %s:%d (host IS listening) - the "+
			"guest→host default-deny should permit only the DNS/HTTP filter ports",
			gateway, listenPort)
	}
}

// TestEgressFailClosedRegression is the positive fail-closed guard for the
// isolation changes: the most likely silent failure of a topology/firewall
// change is breaking legitimate egress (fail-closed), which the negative tests
// above cannot catch. It asserts the sanctioned paths all still work end to end:
// the guest is reachable at its static IP, an allowlisted domain resolves, and both HTTP
// and HTTPS to that domain succeed through the proxy. Topology-independent: these
// must hold on the current NAT topology and after a host-only migration.
func TestEgressFailClosedRegression(t *testing.T) {
	skipIfBackendUnavailable(t)
	skipIfNoConfiguredBaseImage(t)
	skipInShortMode(t)

	env := newTestEnv(t)
	inst := env.newTestInstance()
	inst.create()
	inst.start()

	if !inst.waitForRunning(60 * time.Second) {
		t.Fatal("Instance did not start")
	}

	if !inst.waitForSSH(120 * time.Second) {
		t.Fatal("SSH did not become available")
	}

	// HTTPS through the MITM proxy needs the guest to trust our CA, installed by
	// cloud-init runcmd, which may finish after SSH is up.
	inst.waitForCloudInit()

	inst.allowlistAdd("example.com")
	inst.setFilterMode("active")

	t.Run("guest-has-static-ip", func(t *testing.T) {
		// Successful SSH already implies the guest is reachable at its static IP, but
		// assert an address on the guest NIC explicitly so a networking break surfaces
		// here rather than as an opaque SSH-timeout elsewhere.
		result := inst.ssh("ip", "-4", "-o", "addr", "show", "scope", "global")
		if !result.Success() || !strings.Contains(result.Stdout, "inet ") {
			t.Errorf("guest should have a global IPv4 address (static); got: %q / %v",
				result.Stdout, result.Stderr)
		}
	})

	t.Run("allowlisted-domain-resolves", func(t *testing.T) {
		result := inst.waitForSSHCondition(15*time.Second, 2*time.Second, func(r *runResult) bool {
			return r.Success()
		}, "getent", "ahosts", "example.com")
		if !result.Success() {
			t.Errorf("allowlisted domain should resolve: %s", result.Stderr)
		}
	})

	t.Run("allowlisted-http-succeeds", func(t *testing.T) {
		// http_proxy is configured in the guest by cloud-init, so plain curl uses it.
		result := inst.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
			return r.Success() && strings.TrimSpace(r.Stdout) == "200"
		}, "curl", "-s", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "http://example.com")
		if code := strings.TrimSpace(result.Stdout); code != "200" {
			t.Errorf("allowlisted HTTP should succeed through the proxy, got http_code=%q: %s",
				code, result.Stderr)
		}
	})

	t.Run("allowlisted-https-succeeds", func(t *testing.T) {
		// HTTPS exercises the MITM path (CONNECT allowed + re-encrypt against our CA).
		result := inst.waitForSSHCondition(30*time.Second, 3*time.Second, func(r *runResult) bool {
			return r.Success() && strings.TrimSpace(r.Stdout) == "200"
		}, "curl", "-s", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com")
		if code := strings.TrimSpace(result.Stdout); code != "200" {
			t.Errorf("allowlisted HTTPS should succeed through the MITM proxy, got http_code=%q: %s",
				code, result.Stderr)
		}
	})
}
