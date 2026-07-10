//go:build darwin

package privilege

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Placeholder token kinds used in pfRuleTemplates.
const (
	tokIP     = "<ip>"
	tokBridge = "<bridge>"
	tokPort   = "<port>"
)

// PF instance-rule validation.
//
// PfctlLoadAnchor writes caller-supplied text to a file and runs
// `pfctl -a abox/<name> -f` as root. The anchor namespaces *where* the rules
// live, not *what* they match: a token-holding caller could otherwise load
// arbitrary pf text (e.g. an `rdr` rule hijacking host traffic, or a nested
// `anchor`/`load anchor`/`include` that escapes the sandbox). The unprivileged
// firewall package builds the legitimate ruleset, but client-side validation is
// not a trust boundary — the helper must independently constrain the content.
//
// Rather than parse the full pf grammar, this validator re-derives the exact
// set of rule shapes the legitimate generator emits (see
// internal/firewall/pfctl.go buildInstanceRules) and rejects anything that does
// not match one of them token-for-token. Every variable token (IP, bridge,
// port) is constrained to a safe class. This is the server-side equivalent of
// re-deriving the ruleset from structured fields, working within the existing
// RPC message (InstanceName + RulesContent), and it accepts every ruleset the
// client currently produces while rejecting all other pf directives —
// including anchor/load/include and any file path, none of which can match a
// template.

// pfBridgeNameRE matches vmnet bridge interface names (bridge100, …). Kept in
// sync with internal/firewall.bridgeNameRE; duplicated here because the helper
// must not depend on client-side validation for its own trust boundary.
var pfBridgeNameRE = regexp.MustCompile(`^bridge[0-9]+$`)

// pfRuleTemplate describes one legitimate rule line as a sequence of literal
// keywords and typed placeholders. Each line in the supplied ruleset must match
// exactly one template, token-for-token (single-space separated).
type pfRuleTemplate struct {
	// tokens is the whitespace-split shape of the rule. A token is either a
	// literal keyword (matched verbatim) or a placeholder of the form
	// "<kind>" handled by validatePFToken.
	tokens []string
}

// pfRuleTemplates enumerates every rule shape buildInstanceRules emits. Keeping
// these as data (rather than regexps over the whole line) makes the allowed
// surface auditable directly against the generator.
var pfRuleTemplates = []pfRuleTemplate{
	// rdr pass proto udp from <vmIP> to any port 53 -> 127.0.0.1 port <dnsPort>
	{tokens: strings.Fields("rdr pass proto udp from <ip> to any port 53 -> 127.0.0.1 port <port>")},
	// rdr pass proto tcp from <vmIP> to any port 53 -> 127.0.0.1 port <dnsPort>
	{tokens: strings.Fields("rdr pass proto tcp from <ip> to any port 53 -> 127.0.0.1 port <port>")},
	// block drop quick on <bridge> inet6 all
	{tokens: strings.Fields("block drop quick on <bridge> inet6 all")},
	// pass quick proto udp from <vmIP> port 68 to any port 67
	{tokens: strings.Fields("pass quick proto udp from <ip> port 68 to any port 67")},
	// pass quick proto tcp from <vmIP> to <gateway> port <httpPort>
	{tokens: strings.Fields("pass quick proto tcp from <ip> to <ip> port <port>")},
	// pass quick proto icmp from <vmIP> to <gateway>
	{tokens: strings.Fields("pass quick proto icmp from <ip> to <ip>")},
	// block drop quick from <vmIP> to any
	{tokens: strings.Fields("block drop quick from <ip> to any")},
}

// validatePFRules validates caller-supplied PF instance rules before they are
// written to a file and loaded into a root anchor. It returns nil only if every
// non-blank, non-comment line matches one of pfRuleTemplates exactly.
func validatePFRules(content string) error {
	if strings.TrimSpace(content) == "" {
		return errors.New("rules content is required")
	}
	// Reject embedded NUL outright — pfctl reads a text file and a NUL is never
	// part of a legitimate rule; it also defeats line-oriented parsing.
	if strings.ContainsRune(content, '\x00') {
		return errors.New("rules content contains a NUL byte")
	}

	matchedRule := false
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
		// never does that — strip any inline comment defensively and validate
		// the rule portion. Anything before '#' must still match a template.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		if err := validatePFRuleLine(line); err != nil {
			return fmt.Errorf("line %d: %w", i+1, err)
		}
		matchedRule = true
	}

	if !matchedRule {
		return errors.New("rules content has no valid rule lines")
	}
	return nil
}

// validatePFRuleLine validates a single (trimmed, comment-stripped) rule line
// against the template set.
func validatePFRuleLine(line string) error {
	// Reject any character outside the safe class up front. Legitimate rules use
	// only these; this blocks shell/pf metacharacters (;, {, }, "(", quotes,
	// backslashes, etc.) and, critically, '/' — so no file path or table file
	// reference (`table <t> file "..."`) can appear.
	for _, r := range line {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == ' ' || r == '.' || r == '-' || r == '>':
		default:
			return fmt.Errorf("rule contains disallowed character %q: %q", r, line)
		}
	}

	tokens := strings.Fields(line)
	for _, tmpl := range pfRuleTemplates {
		if matchPFTemplate(tokens, tmpl.tokens) {
			return nil
		}
	}
	return fmt.Errorf("rule does not match any allowed shape: %q", line)
}

// matchPFTemplate reports whether tokens match the template token-for-token.
func matchPFTemplate(tokens, tmpl []string) bool {
	if len(tokens) != len(tmpl) {
		return false
	}
	for i, t := range tmpl {
		switch t {
		case tokIP, tokBridge, tokPort:
			if !validatePFToken(t, tokens[i]) {
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

// validatePFToken validates a single placeholder token value.
func validatePFToken(kind, value string) bool {
	switch kind {
	case tokIP:
		ip := net.ParseIP(value)
		// IPv4 only: the generator only ever emits IPv4 source/dest addresses
		// (IPv6 is killed wholesale by the inet6 block rule).
		return ip != nil && ip.To4() != nil && !strings.Contains(value, ":")
	case tokBridge:
		return pfBridgeNameRE.MatchString(value)
	case tokPort:
		n, err := strconv.Atoi(value)
		if err != nil {
			return false
		}
		// Dynamic dnsfilter/httpfilter ports are always unprivileged. Matches
		// the client-side validatePfctlArgs port range.
		return n >= 1024 && n <= 65535
	default:
		return false
	}
}
