package boxfile

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/errhint"
)

// The yaml decoder reports each problem as "line N: <detail>", e.g.
//
//	line 7: field mtim not found in type boxfile.BoxfileHTTP
//	line 9: cannot unmarshal !!str `abc` into int
//
// linePrefixRe splits off the line number; unknownFieldRe recognizes the
// unknown-key detail that KnownFields(true) produces. Details that are not
// unknown-key problems (ordinary type errors) are reported verbatim rather than
// dropped.
// The key is matched with .+ rather than \S+: yaml keys may contain spaces
// ("max connections:" is a plausible typo for max_connections), and a \S+ key
// pattern would fail to match, falling through to the verbatim branch and
// leaking the Go type name into user-facing output. The literal " not found in
// type " and the anchors bound the match.
var (
	linePrefixRe   = regexp.MustCompile(`^line (\d+): (.*)$`)
	unknownFieldRe = regexp.MustCompile(`^field (.+) not found in type (\S+)$`)
)

// boxfileTypes maps the Go type names that leak into yaml decode errors to the
// abox.yaml key path they live under, so a user sees "http.mtim" rather than
// "boxfile.BoxfileHTTP". The names are package-qualified because that is what
// reflect.Type.String() — and therefore the decoder — produces.
//
// The reflect.Type is kept so suggestions can be drawn from the same type the
// decoder rejected the key against.
var boxfileTypes = map[string]struct {
	prefix string
	typ    reflect.Type
}{
	"boxfile.Boxfile":        {"", reflect.TypeFor[Boxfile]()},
	"boxfile.BoxfileDNS":     {"dns", reflect.TypeFor[BoxfileDNS]()},
	"boxfile.BoxfileHTTP":    {"http", reflect.TypeFor[BoxfileHTTP]()},
	"boxfile.BoxfileMonitor": {"monitor", reflect.TypeFor[BoxfileMonitor]()},
	"config.SecretInjection": {"http.secret_injections", reflect.TypeFor[config.SecretInjection]()},
}

// decodeError converts a yaml decode failure into the house error style: a
// single lowercase line naming the file and the dotted key, with any
// "did you mean" guidance and the full problem list carried in an ErrHint so
// the CLI renders it below the message.
//
// Errors that are not *yaml.TypeError (malformed YAML, IO) are wrapped
// unchanged.
func decodeError(name string, err error) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return fmt.Errorf("failed to parse %s: %w", name, err)
	}

	problems := make([]string, 0, len(typeErr.Errors))
	var suggestions []string
	for _, entry := range typeErr.Errors {
		problem, suggestion := describeEntry(name, entry)
		problems = append(problems, problem)
		if suggestion != "" {
			suggestions = append(suggestions, suggestion)
		}
	}

	if len(problems) == 0 { // defensive: a TypeError with no entries
		return fmt.Errorf("failed to parse %s: %w", name, err)
	}

	var hint strings.Builder
	if len(problems) > 1 {
		for _, p := range problems {
			fmt.Fprintf(&hint, "  %s\n", p)
		}
		hint.WriteString("\n")
	}
	for _, s := range suggestions {
		hint.WriteString(s + "\n")
	}
	if len(suggestions) > 0 {
		hint.WriteString("\n")
	}
	hint.WriteString("see 'abox yaml' for the full key reference")

	msg := problems[0]
	if len(problems) > 1 {
		msg = fmt.Sprintf("%d problems in %s", len(problems), name)
	}
	return &errhint.ErrHint{Err: errors.New(msg), Hint: hint.String()}
}

// describeEntry renders one decoder error entry as a user-facing problem line,
// plus a "did you mean" suggestion when the entry is a recognizable typo.
// Entries that are not unknown-key problems (type mismatches) are reported
// verbatim so nothing is swallowed.
func describeEntry(name, entry string) (problem, suggestion string) {
	where, detail := name, entry
	if m := linePrefixRe.FindStringSubmatch(entry); m != nil {
		where, detail = fmt.Sprintf("%s line %s", name, m[1]), m[2]
	}

	m := unknownFieldRe.FindStringSubmatch(detail)
	if m == nil {
		return fmt.Sprintf("%s: %s", where, detail), ""
	}
	field, goType := m[1], m[2]

	known, ok := boxfileTypes[goType]
	if !ok {
		// A nested type we have no key path for: report the bare key rather
		// than leaking the Go type name.
		return fmt.Sprintf("%s: unknown key %q", where, field), ""
	}

	key := field
	if known.prefix != "" {
		key = known.prefix + "." + field
	}
	problem = fmt.Sprintf("%s: unknown key %q", where, key)

	match := closest(field, yamlFieldNames(known.typ))
	if match == "" {
		return problem, ""
	}
	if known.prefix != "" {
		match = known.prefix + "." + match
	}
	return problem, fmt.Sprintf("did you mean %q?", match)
}

// yamlFieldNames returns the yaml key names a struct type accepts. An untagged
// exported field is bound by yaml under its lowercased name, so it is included
// too — otherwise a suggestion could never propose it.
func yamlFieldNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for f := range t.Fields() {
		if f.PkgPath != "" { // unexported
			continue
		}
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		switch tag {
		case "-":
		case "":
			names = append(names, strings.ToLower(f.Name))
		default:
			names = append(names, tag)
		}
	}
	return names
}

// closest returns the candidate nearest to name by edit distance, or "" when
// none is close enough to be worth suggesting. The threshold scales with the
// length of the key so short keys don't attract unrelated matches.
func closest(name string, candidates []string) string {
	name = strings.ToLower(name)
	limit := max(2, len(name)/3)

	best, bestDist := "", limit+1
	for _, c := range candidates {
		if d := editDistance(name, strings.ToLower(c)); d < bestDist {
			best, bestDist = c, d
		}
	}
	if bestDist > limit {
		return ""
	}
	return best
}

// editDistance is the Levenshtein distance between a and b, computed with two
// rows rather than a full matrix.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(min(curr[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}
