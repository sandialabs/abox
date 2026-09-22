package httpfilter

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/sandialabs/abox/internal/allowlist"
	"github.com/sandialabs/abox/internal/logging"
)

// SecretRule is a resolved secret-injection binding. serve.go builds these from
// config.SecretInjection + the secret store so that httpfilter stays
// config-agnostic. Value is the fully-resolved header value (value_prefix +
// stored secret). When Strip is true the header is removed from the outbound
// request instead of being set (used when a binding's key has no stored value,
// so the guest can never supply its own credential to a bound host).
type SecretRule struct {
	Key        string // secret store key name (for audit only; never the value)
	Host       string // exact host; canonicalized internally
	Header     string
	Value      string
	PathPrefix string
	Strip      bool
}

// mitmContextKey marks a request as genuinely CONNECT-intercepted (MITM'd) rather
// than a forward-proxy absolute-URI request. Injection fires only for the former:
// a forward-proxy request's target host is fully guest-controlled via the request
// line and was never pinned by CONNECT, so injecting there would defeat the
// unspoofable-host guarantee.
type mitmContextKey struct{}

func withMITM(ctx context.Context) context.Context {
	return context.WithValue(ctx, mitmContextKey{}, true)
}

func isMITM(ctx context.Context) bool {
	v, _ := ctx.Value(mitmContextKey{}).(bool)
	return v
}

// canonicalHost reduces a host to the single canonical form used as the injection
// map key on both the binding side and the request side. NormalizeDomain
// lowercases, punycodes, and appends a trailing dot; extractHost does not append
// one, so we trim it to keep both sides identical.
func canonicalHost(host string) string {
	return strings.TrimSuffix(allowlist.NormalizeDomain(host), ".")
}

// SetSecretInjections atomically replaces the active injection rule set. The rules
// are grouped by canonical host into an immutable map published via an atomic
// pointer, so the request-path reader never locks and never observes a partial
// update. Passing nil/empty clears all injections.
//
// It emits one audit record per configured binding (host + key + header + whether
// it injects or strips, never the value) so both outcomes of a binding — a live
// credential injection, or a value-less binding degraded to header-stripping — are
// captured once at apply time rather than on every request.
func (s *Server) SetSecretInjections(instance string, rules []SecretRule) {
	m := make(map[string][]SecretRule, len(rules))
	for _, r := range rules {
		key := canonicalHost(r.Host)
		m[key] = append(m[key], r)
		logging.AuditInstance(instance, logging.ActionSecretInject,
			"filter", "http", "host", r.Host, "key", r.Key, "header", r.Header, "strip", r.Strip)
	}
	s.secretInjections.Store(&m)
}

// safeCleanPath returns a traversal-normalized absolute path for prefix matching,
// or ok=false if the request must not be considered for injection. It rejects any
// request whose path carried non-canonical percent-encoding (e.g. %2f-encoded
// separators, the classic prefix-bypass vector): url.URL only populates RawPath
// when the escaped form differs from the default encoding of Path, so a non-empty
// RawPath signals an encoding we refuse to reason about. The remaining ".." / "//"
// segments are collapsed by path.Clean.
func safeCleanPath(u *url.URL) (string, bool) {
	if u.RawPath != "" {
		return "", false
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	clean := path.Clean(p)
	// path.Clean neutralizes ".." on an absolute path; a residual ".." would mean
	// a relative/odd input we should not trust for a security gate.
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

// matchPrefix reports whether clean is within the pathPrefix, on a path-segment
// boundary. A naive strings.HasPrefix would let prefix "/v1" match "/v10/foo";
// this requires an exact match or a following "/".
func matchPrefix(clean, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return true // "/" (or empty) matches every path
	}
	return clean == prefix || strings.HasPrefix(clean, prefix+"/")
}

// injectSecrets is the ReverseProxy.Rewrite hook. It runs after decideRequest has
// already authorized forwarding, on the cloned outbound request (pr.Out), and only
// for genuine MITM'd HTTPS requests to a bound host on a permitted path.
func (s *Server) injectSecrets(pr *httputil.ProxyRequest) {
	if !isMITM(pr.In.Context()) {
		return // forward-proxy absolute-URI or non-intercepted: never inject
	}
	// Passive mode forwards every host for profiling; never transmit live
	// credentials in that mode. serve.go refuses to start in passive with
	// injections configured, but the mode can also be flipped to passive at
	// runtime via the API, so re-check here (defense in depth).
	if !s.IsActive() {
		return
	}
	// Fast path: skip the host canonicalization (IDNA) cost entirely when no
	// injections are configured, which is the common case.
	m := s.secretInjections.Load()
	if m == nil || len(*m) == 0 {
		return
	}
	host := extractHost(pr.Out.URL.Host)
	rules := (*m)[canonicalHost(host)]
	if len(rules) == 0 {
		return
	}
	// clean/ok describe the request path. When the path cannot be safely
	// normalized (e.g. percent-encoded separators), no inject rule applies, but
	// strip rules still fire — removing a header can never leak a secret.
	clean, ok := safeCleanPath(pr.Out.URL)
	// TRACE echoes the request verbatim in its response, so injecting a secret on
	// a TRACE would hand it straight back to the guest. Never inject on TRACE
	// (strip rules still apply, so the guest can't smuggle its own credential).
	echoMethod := pr.Out.Method == http.MethodTrace
	for _, r := range rules {
		pathApplies := ok && (r.PathPrefix == "" || matchPrefix(clean, r.PathPrefix))
		if r.Strip {
			// A value-less binding must never let the guest supply its own
			// credential to the bound host: strip wherever we would have injected,
			// and fail closed by stripping when the path is unparseable.
			if pathApplies || !ok {
				pr.Out.Header.Del(r.Header)
			}
			continue
		}
		if !pathApplies {
			continue
		}
		if echoMethod {
			// TRACE would echo the request back; never inject here. Also remove any
			// header the guest supplied, so it can't smuggle its own credential to
			// the bound host on the injected path.
			pr.Out.Header.Del(r.Header)
			continue
		}
		// Set overrides any header the guest supplied, so the guest can neither
		// probe nor pre-empt the injected credential.
		pr.Out.Header.Set(r.Header, r.Value)
		// Debug (not audit): logged per request. The audit record was emitted once
		// at apply time in SetSecretInjections. Never logs the value.
		logging.Debug("injected secret header", "host", host, "header", r.Header)
	}
}
