package boxfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sandialabs/abox/internal/config"
)

// Trust gating for repo-supplied abox.yaml.
//
// A repository's abox.yaml is a wider trust surface than an operator's own
// environment: it can replace the hardened VM template, pull arbitrary host paths
// into the guest, re-open SSRF private targets, disable MITM, and widen the proxy
// port allowlist. On first use of a security-relevant abox.yaml, abox summarizes
// those settings and requires explicit confirmation (direnv-style), remembering
// the approval keyed by directory AND content fingerprint.

// SecuritySummary returns a human-readable line for each non-default,
// security-relevant setting in the boxfile. An empty result means nothing
// security-relevant is set, so the trust gate can be skipped silently.
func SecuritySummary(b *Boxfile) []string {
	out := summarizeOverrides(b)
	out = append(out, summarizeAbsolutePaths(b)...)

	// SSRF re-opening.
	if len(b.HTTP.AllowPrivateTargets) > 0 {
		out = append(out, "http.allow_private_targets re-opens SSRF-blocked ranges: "+strings.Join(b.HTTP.AllowPrivateTargets, ", "))
	}

	// MITM disabled: inner HTTPS traffic is not inspected.
	if b.HTTP.MITM != nil && !*b.HTTP.MITM {
		out = append(out, "http.mitm: false (TLS inspection disabled)")
	}

	// MITM exceptions: listed domains are tunneled without TLS inspection,
	// forfeiting inner-Host/domain-fronting checks for them — a per-domain
	// form of the http.mitm: false downgrade above.
	if len(b.HTTP.MITMExceptions) > 0 {
		out = append(out, "http.mitm_exceptions tunnels domains without TLS inspection: "+strings.Join(b.HTTP.MITMExceptions, ", "))
	}

	// Widened destination-port allowlist: reaching allowlisted hosts on
	// non-default ports.
	if len(b.HTTP.AllowedPorts) > 0 {
		out = append(out, "http.allowed_ports widens reachable ports: "+joinInts(b.HTTP.AllowedPorts))
	}

	// Secret injection binds a host-side secret into outbound request headers for
	// a specific host — a hostile binding (or re-target of an existing secret to an
	// attacker host/header) can exfiltrate the credential.
	for _, si := range b.HTTP.SecretInjections {
		out = append(out, fmt.Sprintf("http.secret_injections binds secret %q into header %q for host %q", si.Key, si.Header, si.Host))
	}

	// Custom upstream DNS: redirects the guest's resolver to a chosen server,
	// enabling answer manipulation / query metadata collection. Empty = host's
	// system resolver (the default).
	if b.DNS.Upstream != "" {
		out = append(out, "dns.upstream redirects guest DNS to "+b.DNS.Upstream)
	}

	return out
}

// summarizeOverrides flags custom templates (bypass VM hardening) and any
// absolute-path override values.
func summarizeOverrides(b *Boxfile) []string {
	var out []string
	for _, backend := range sortedKeys(b.Overrides) {
		for _, key := range sortedKeys(b.Overrides[backend]) {
			v := b.Overrides[backend][key]
			switch {
			case key == overrideKeyTemplate && v != "":
				out = append(out, fmt.Sprintf("custom %s template %q (bypasses VM hardening: QEMU sandbox, device restrictions, memory isolation)", backend, v))
			case filepath.IsAbs(v):
				out = append(out, fmt.Sprintf("override %s.%s uses absolute host path %q", backend, key, v))
			}
		}
	}
	return out
}

// summarizeAbsolutePaths flags provision/overlay/monitor-policy entries that
// reach outside the repo directory via an absolute host path.
func summarizeAbsolutePaths(b *Boxfile) []string {
	var out []string
	for _, p := range b.Provision {
		if filepath.IsAbs(p) {
			out = append(out, fmt.Sprintf("provision script uses absolute host path %q", p))
		}
	}
	if filepath.IsAbs(b.Overlay) {
		out = append(out, fmt.Sprintf("overlay copies absolute host path %q into the guest", b.Overlay))
	}
	for _, p := range b.Monitor.Policies {
		if filepath.IsAbs(p) {
			out = append(out, fmt.Sprintf("monitor policy uses absolute host path %q", p))
		}
	}
	return out
}

// TrustFingerprint returns a hex sha256 over the raw abox.yaml bytes PLUS the
// content of every referenced host-side file whose tampering would change
// security posture (custom templates, monitor policies). Hashing only the yaml
// bytes would let an attacker swap a referenced file after the user trusts it,
// silently bypassing the gate. baseDir is the abox.yaml directory (for resolving
// referenced paths); a referenced file that cannot be read is folded in as an
// error marker so the fingerprint still changes rather than silently ignoring it.
func TrustFingerprint(b *Boxfile, rawYAML []byte, baseDir string) string {
	h := sha256.New()
	h.Write(rawYAML)

	// Referenced host-side files, in a deterministic order.
	var refs []string
	for _, backend := range sortedKeys(b.Overrides) {
		if b.Overrides[backend][overrideKeyTemplate] != "" {
			refs = append(refs, "template:"+backend)
		}
	}
	for i := range b.Monitor.Policies {
		refs = append(refs, "policy:"+strconv.Itoa(i))
	}
	sort.Strings(refs)

	for _, ref := range refs {
		h.Write([]byte("\x00" + ref + "\x00"))
		var (
			content []byte
			err     error
		)
		switch {
		case strings.HasPrefix(ref, "template:"):
			backend := strings.TrimPrefix(ref, "template:")
			var s string
			s, err = b.LoadOverrideContent(backend, overrideKeyTemplate, baseDir)
			content = []byte(s)
		case strings.HasPrefix(ref, "policy:"):
			var paths []string
			if paths, err = b.ResolvePolicyPaths(baseDir); err == nil {
				content, err = os.ReadFile(paths[policyIndex(ref)])
			}
		}
		if err != nil {
			h.Write([]byte("ERR:" + err.Error()))
			continue
		}
		h.Write(content)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func policyIndex(ref string) int {
	i, _ := strconv.Atoi(strings.TrimPrefix(ref, "policy:"))
	return i
}

// trustCache maps an absolute boxfile directory to the trusted fingerprint.
type trustCache map[string]string

func trustCachePath() (string, error) {
	paths, err := config.GetPaths("")
	if err != nil {
		return "", err
	}
	return filepath.Join(paths.Base, "trusted-boxfiles.json"), nil
}

func loadTrustCache() (trustCache, error) {
	path, err := trustCachePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return trustCache{}, nil
		}
		return nil, err
	}
	tc := trustCache{}
	if err := json.Unmarshal(data, &tc); err != nil {
		// A corrupt cache should not brick create/up; treat as empty (nothing
		// trusted), so the gate re-prompts rather than failing open or closed hard.
		return trustCache{}, nil //nolint:nilerr // corrupt cache => empty (nothing trusted); re-prompt
	}
	return tc, nil
}

// IsTrusted reports whether boxDir has been trusted at EXACTLY this fingerprint.
// It requires fingerprint equality, not mere presence of the directory key, so a
// previously-trusted repo at a path does not auto-trust a different (malicious)
// repo later checked out to the same path.
func IsTrusted(boxDir, fingerprint string) (bool, error) {
	tc, err := loadTrustCache()
	if err != nil {
		return false, err
	}
	return tc[boxDir] == fingerprint, nil
}

// MarkTrusted records boxDir->fingerprint in the trust cache (0600).
func MarkTrusted(boxDir, fingerprint string) error {
	path, err := trustCachePath()
	if err != nil {
		return err
	}
	tc, err := loadTrustCache()
	if err != nil {
		return err
	}
	tc[boxDir] = fingerprint
	data, err := json.MarshalIndent(tc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ", ")
}
