//go:build darwin

package privilege

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sandialabs/abox/internal/pfvalidate"
)

// Placeholder token kinds used in pfRuleTemplates.
const (
	tokCIDR   = "<cidr>"   // the instance's /24 subnet (bound to req.subnet)
	tokGw     = "<gw>"     // the subnet gateway (.1 host of req.subnet)
	tokBridge = "<bridge>" // the VM bridge interface (bridge[0-9]+ or vmnet[0-9]+)
	tokPort   = "<port>"   // an unprivileged dnsfilter/httpfilter port
)

// PF instance-rule validation.
//
// LoadAnchor feeds caller-supplied text to `pfctl -a abox/<name> -f -` (STDIN)
// as root. The anchor namespaces *where* the rules live, not *what* they match:
// a token-holding caller could otherwise load arbitrary pf text (e.g. an `rdr`
// rule hijacking host traffic, or a nested `anchor`/`load anchor`/`include`
// that escapes the sandbox), or — the case this validator specifically closes —
// rules keyed on *another* instance's subnet, letting one instance rewrite a
// peer's egress. The unprivileged firewall package builds the legitimate
// ruleset, but client-side validation is not a trust boundary — the helper must
// independently constrain the content.
//
// Rather than parse the full pf grammar, this validator re-derives the exact set
// of rule shapes the legitimate generator emits (see
// internal/firewall/pfctl.go BuildInstanceRules) and rejects anything that does
// not match one of them token-for-token. Every variable token is constrained to
// a safe class AND bound to the caller's declared subnet: <cidr> must equal the
// subnet, <gw> must equal its .1 gateway. This means a caller literally cannot
// express a rule that matches a subnet other than the one it passed, which is
// what the server independently enforces per instance.

// pfRuleTemplate describes one legitimate rule line as a sequence of literal
// keywords and typed placeholders. Each line in the supplied ruleset must match
// exactly one template, token-for-token (single-space separated).
type pfRuleTemplate struct {
	// tokens is the whitespace-split shape of the rule. A token is either a
	// literal keyword (matched verbatim) or a placeholder of the form
	// "<kind>" handled by validatePFToken.
	tokens []string
}

// terminalDenyTemplate is the subnet-keyed default-deny that must terminate
// every instance ruleset. A pf anchor with no matching rule falls through to
// "pass", so this line is what makes the anchor fail-closed: a ruleset of only
// allow rules would leave the guest able to reach anything not explicitly
// blocked. validatePFRules requires at least one line matching this template.
var terminalDenyTemplate = pfRuleTemplate{tokens: strings.Fields("block drop quick from <cidr> to any")}

// inet6DenyTemplate is the interface-scoped IPv6 kill. vmnet has no flag to
// disable NAT66/link-local IPv6, and the subnet-keyed terminal deny is IPv4-only,
// so this is the ONLY line that closes IPv6 egress. validatePFRules requires it
// in any ruleset that also carries allow rules (see the hasInet6Deny gate) so a
// buggy or compromised token-holder cannot load a full egress ruleset that denies
// IPv4 but leaves IPv6 open.
var inet6DenyTemplate = pfRuleTemplate{tokens: strings.Fields("block drop quick on <bridge> inet6 all")}

// pfRuleTemplates enumerates every rule shape BuildInstanceRules emits. Keeping
// these as data (rather than regexps over the whole line) makes the allowed
// surface auditable directly against the generator.
var pfRuleTemplates = []pfRuleTemplate{
	// rdr pass proto udp from <cidr> to any port 53 -> 127.0.0.1 port <port>
	{tokens: strings.Fields("rdr pass proto udp from <cidr> to any port 53 -> 127.0.0.1 port <port>")},
	// rdr pass proto tcp from <cidr> to any port 53 -> 127.0.0.1 port <port>
	{tokens: strings.Fields("rdr pass proto tcp from <cidr> to any port 53 -> 127.0.0.1 port <port>")},
	// block drop quick on <bridge> inet6 all
	inet6DenyTemplate,
	// pass quick proto tcp from <cidr> to <gw> port <port>
	{tokens: strings.Fields("pass quick proto tcp from <cidr> to <gw> port <port>")},
	// pass quick proto icmp from <cidr> to <gw>
	{tokens: strings.Fields("pass quick proto icmp from <cidr> to <gw>")},
	// pass quick proto tcp from <gw> to <cidr> port 22 (host->guest SSH; note the
	// from/to order is inverted vs the egress rules — the connection is inbound,
	// initiated by the host at the gateway address. The reply rides pf state.)
	{tokens: strings.Fields("pass quick proto tcp from <gw> to <cidr> port 22")},
	// block drop quick proto tcp from ! <cidr> to any port <port> (deny inbound to
	// the HTTP proxy from outside the subnet; the proxy binds the wildcard address)
	{tokens: strings.Fields("block drop quick proto tcp from ! <cidr> to any port <port>")},
	// block drop quick from <cidr> to any (terminal default-deny; required)
	terminalDenyTemplate,
}

// validatePFRules validates caller-supplied PF instance rules before they are
// loaded into a root anchor. It returns nil only if every non-blank,
// non-comment line matches one of pfRuleTemplates exactly, with each variable
// token bound to subnet (see file-level doc). subnet must be a valid /24 CIDR.
func validatePFRules(content, subnet string) error {
	if strings.TrimSpace(content) == "" {
		return errors.New("rules content is required")
	}
	// Reject embedded NUL outright — pfctl reads text and a NUL is never part of
	// a legitimate rule; it also defeats line-oriented parsing.
	if strings.ContainsRune(content, '\x00') {
		return errors.New("rules content contains a NUL byte")
	}

	cidr, gw, err := subnetTokens(subnet)
	if err != nil {
		return err
	}

	scan, err := scanPFRuleLines(content, cidr, gw)
	if err != nil {
		return err
	}

	if !scan.matched {
		return errors.New("rules content has no valid rule lines")
	}
	// Defense-in-depth: even though every line matched an allowed shape, a
	// ruleset without the subnet-keyed terminal deny is fail-open (a pf anchor
	// falls through to "pass"). Refuse to load one so a buggy or compromised
	// token-holder cannot silently drop the guest's default-deny.
	if !scan.terminalDeny {
		return errors.New("rules are missing the terminal default-deny (block drop quick from <subnet> to any); refusing to load a fail-open ruleset")
	}
	// The IPv4 terminal deny does not cover IPv6 (vmnet's NAT66/link-local v6 has
	// no disable flag), so a ruleset that permits egress but omits the inet6 kill
	// leaves IPv6 fail-open. Require the inet6 deny whenever allow rules are
	// present. The pre-boot ruleset (the IPv4 inbound-proxy confinement plus the
	// IPv4 terminal deny — both "block" lines, no allow rules, and no bridge to
	// scope an inet6 rule on) is intentionally exempt.
	if scan.allow && !scan.inet6Deny {
		return errors.New("egress ruleset permits traffic but is missing the IPv6 default-deny (block drop quick on <bridge> inet6 all); refusing to load a ruleset that leaves IPv6 unfiltered")
	}
	return nil
}

// pfRuleScan records what a single pass over the rule lines observed: whether
// any valid rule matched and which required-shape rules (terminal deny, inet6
// deny, an allow rule) were present.
type pfRuleScan struct {
	matched      bool
	terminalDeny bool
	inet6Deny    bool
	allow        bool
}

// scanPFRuleLines walks content line by line, validating each non-blank,
// non-comment line against the templates (bound to cidr/gw) and recording which
// required rule shapes were seen. It returns an error carrying the 1-based line
// number on the first invalid line.
func scanPFRuleLines(content, cidr, gw string) (pfRuleScan, error) {
	var scan pfRuleScan
	for i, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Comment. A '#' anywhere starts a pf comment to end of line, and we
			// already split on '\n', so a comment line cannot smuggle a second
			// directive. No file paths or directives can execute from here.
			continue
		}
		// A bare '#' may also appear after a directive in pf, but the generator
		// never does that — reject any inline '#' outright rather than strip it,
		// so an attacker cannot hide a mismatching rule behind a trailing
		// comment that happens to make the prefix match a template.
		if strings.IndexByte(line, '#') >= 0 {
			return scan, fmt.Errorf("line %d: inline comments are not allowed: %q", i+1, line)
		}

		if err := validatePFRuleLine(line, cidr, gw); err != nil {
			return scan, fmt.Errorf("line %d: %w", i+1, err)
		}
		fields := strings.Fields(line)
		if matchPFTemplate(fields, terminalDenyTemplate.tokens, cidr, gw) {
			scan.terminalDeny = true
		}
		if matchPFTemplate(fields, inet6DenyTemplate.tokens, cidr, gw) {
			scan.inet6Deny = true
		}
		// An allow rule is any rdr/pass line — the shapes that actually let the
		// guest reach the network. A ruleset carrying these MUST also close IPv6.
		if strings.HasPrefix(line, "rdr ") || strings.HasPrefix(line, "pass ") {
			scan.allow = true
		}
		scan.matched = true
	}
	return scan, nil
}

// subnetTokens validates subnet as a /24 CIDR and returns the canonical CIDR
// string and its gateway (.1 host) as the tokens every rule line is bound to.
// The /24 parse, network-address check, and .1 derivation live in the shared
// pfvalidate.ParseSubnet24, which the client validates against independently; the
// helper re-derives the tokens here as its own trust boundary.
func subnetTokens(subnet string) (cidr, gw string, err error) {
	network, gateway, err := pfvalidate.ParseSubnet24(subnet)
	if err != nil {
		return "", "", err
	}
	return network.String(), gateway.String(), nil
}

// validatePFRuleLine validates a single (trimmed, comment-free) rule line
// against the template set, binding tokens to cidr/gw.
func validatePFRuleLine(line, cidr, gw string) error {
	// Reject any character outside the safe class up front. Legitimate rules use
	// only these; this blocks shell/pf metacharacters (;, {, }, "(", quotes,
	// backslashes, etc.) and, critically, '/' — wait, '/' appears in <cidr>
	// (10.0.0.0/24), so '/' is permitted, but only as part of a token that must
	// then equal cidr exactly. Everything else stays denied.
	for _, r := range line {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == ' ' || r == '.' || r == '-' || r == '>' || r == '/':
		// '!' is pf's negation, used only in the "from ! <cidr>" inbound-proxy
		// deny. It carries no shell meaning here (content is piped to pfctl, not a
		// shell) and a line using it must still match that template token-for-token.
		case r == '!':
		default:
			return fmt.Errorf("rule contains disallowed character %q: %q", r, line)
		}
	}

	tokens := strings.Fields(line)
	for _, tmpl := range pfRuleTemplates {
		if matchPFTemplate(tokens, tmpl.tokens, cidr, gw) {
			return nil
		}
	}
	return fmt.Errorf("rule does not match any allowed shape: %q", line)
}

// matchPFTemplate reports whether tokens match the template token-for-token,
// with variable tokens bound to cidr/gw.
func matchPFTemplate(tokens, tmpl []string, cidr, gw string) bool {
	if len(tokens) != len(tmpl) {
		return false
	}
	for i, t := range tmpl {
		switch t {
		case tokCIDR, tokGw, tokBridge, tokPort:
			if !validatePFToken(t, tokens[i], cidr, gw) {
				return false
			}
		default:
			if tokens[i] != t {
				return false
			}
		}
	}
	return true
}

// validatePFToken validates a single placeholder token value and binds it to
// the caller's subnet where applicable.
func validatePFToken(kind, value, cidr, gw string) bool {
	switch kind {
	case tokCIDR:
		// Bound: must be exactly the caller's subnet. This is the cross-instance
		// injection guard — a caller cannot write rules matching another
		// instance's subnet.
		return value == cidr
	case tokGw:
		// Bound: must be exactly the subnet's .1 gateway.
		return value == gw
	case tokBridge:
		return pfvalidate.MatchBridgeName(value)
	case tokPort:
		n, err := strconv.Atoi(value)
		if err != nil {
			return false
		}
		// Reject non-canonical forms (leading zeros, "+8080") so the validated
		// token is byte-identical to what pfctl parses from stdin.
		if strconv.Itoa(n) != value {
			return false
		}
		// Dynamic dnsfilter/httpfilter ports are always unprivileged. Shared with
		// the client-side validation port range.
		return pfvalidate.ValidatePort(n)
	default:
		return false
	}
}

// validateInstanceName validates an instance name for use in PF anchors. The
// anchor-safe character rule is shared with the client via
// pfvalidate.ValidateInstanceName; the 63-character cap is a helper-side policy
// (anchor path length) enforced here, keeping the helper no more permissive than
// before.
func validateInstanceName(name string) error {
	if len(name) > 63 {
		return fmt.Errorf("instance name exceeds 63 characters: %s", name)
	}
	return pfvalidate.ValidateInstanceName(name)
}
