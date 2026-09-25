package boxfile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/errhint"
)

// writeBox writes an abox.yaml into a fresh temp dir and returns the dir.
func writeBox(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "abox.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write abox.yaml: %v", err)
	}
	return dir
}

// hintFromErr returns the remediation hint the CLI would render below err.
func hintFromErr(err error) string {
	var h *errhint.ErrHint
	if errors.As(err, &h) {
		return h.Hint
	}
	return ""
}

func TestLoad_RejectsUnknownKey(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantKey string
	}{
		{
			name:    "top level",
			content: "version: 1\nname: t\nmemroy: 4096\n",
			wantKey: `unknown key "memroy"`,
		},
		{
			name:    "http section",
			content: "version: 1\nname: t\nhttp:\n  mtim: true\n",
			wantKey: `unknown key "http.mtim"`,
		},
		{
			name:    "dns section",
			content: "version: 1\nname: t\ndns:\n  upstrem: 8.8.8.8\n",
			wantKey: `unknown key "dns.upstrem"`,
		},
		{
			name:    "monitor section",
			content: "version: 1\nname: t\nmonitor:\n  enabld: true\n",
			wantKey: `unknown key "monitor.enabld"`,
		},
		{
			name:    "secret injection element",
			content: "version: 1\nname: t\nhttp:\n  secret_injections:\n    - key: k\n      hostt: h\n",
			wantKey: `unknown key "http.secret_injections.hostt"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Load(writeBox(t, tt.content))
			if err == nil {
				t.Fatal("Load() error = nil, want unknown-key error")
			}
			if !strings.Contains(err.Error(), tt.wantKey) {
				t.Errorf("Load() error = %q, want it to contain %q", err, tt.wantKey)
			}
			// Go type names must never reach the user.
			for _, leak := range []string{"boxfile.", "Boxfile", "config.SecretInjection"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("Load() error = %q, leaks Go type name %q", err, leak)
				}
			}
		})
	}
}

func TestLoad_UnknownKeySuggestsCorrection(t *testing.T) {
	tests := []struct {
		content string
		want    string
	}{
		{"version: 1\nname: t\nmemroy: 4096\n", `did you mean "memory"?`},
		{"version: 1\nname: t\nhttp:\n  mtim: true\n", `did you mean "http.mitm"?`},
		{"version: 1\nname: t\nmonitor:\n  enabld: true\n", `did you mean "monitor.enabled"?`},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			_, _, err := Load(writeBox(t, tt.content))
			if err == nil {
				t.Fatal("Load() error = nil, want unknown-key error")
			}
			hint := hintFromErr(err)
			if !strings.Contains(hint, tt.want) {
				t.Errorf("hint = %q, want it to contain %q", hint, tt.want)
			}
		})
	}
}

// TestLoad_VersionCheckPrecedesStrict is the ordering guarantee: a boxfile from
// a newer abox must be told to upgrade, not buried in unknown-key errors for
// keys this build simply doesn't have yet.
func TestLoad_VersionCheckPrecedesStrict(t *testing.T) {
	_, _, err := Load(writeBox(t, "version: 99\nname: t\nsome_future_key: yes\n"))
	if err == nil {
		t.Fatal("Load() error = nil, want version error")
	}
	if !strings.Contains(err.Error(), "newer than supported") {
		t.Errorf("Load() error = %q, want the version error to win over strict parsing", err)
	}
	if strings.Contains(err.Error(), "unknown key") {
		t.Errorf("Load() error = %q, want no unknown-key noise for a future version", err)
	}
}

func TestLoad_TypeMismatchStillReported(t *testing.T) {
	_, _, err := Load(writeBox(t, "version: 1\nname: t\ncpus: \"abc\"\n"))
	if err == nil {
		t.Fatal("Load() error = nil, want type error")
	}
	if !strings.Contains(err.Error(), "cannot unmarshal") {
		t.Errorf("Load() error = %q, want the type mismatch preserved", err)
	}
}

func TestLoad_MultipleProblemsListedInHint(t *testing.T) {
	err := func() error {
		_, _, err := Load(writeBox(t, "version: 1\nname: t\nmemroy: 1\nhttp:\n  mtim: true\n"))
		return err
	}()
	if err == nil {
		t.Fatal("Load() error = nil, want unknown-key errors")
	}
	if err.Error() != "2 problems in abox.yaml" {
		t.Errorf("Load() error = %q, want a single-line count summary", err)
	}
	hint := hintFromErr(err)
	for _, want := range []string{`"memroy"`, `"http.mtim"`} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint = %q, want it to list %s", hint, want)
		}
	}
}

func TestLoadLenient_AcceptsUnknownKey(t *testing.T) {
	dir := writeBox(t, "version: 1\nname: teardown-me\nmemroy: 4096\n")

	if _, _, err := Load(dir); err == nil {
		t.Fatal("Load() error = nil; the strict loader must reject the typo")
	}

	box, _, err := LoadLenient(dir)
	if err != nil {
		t.Fatalf("LoadLenient() error = %v; teardown must survive a typo'd boxfile", err)
	}
	if box.Name != "teardown-me" {
		t.Errorf("LoadLenient().Name = %q, want %q", box.Name, "teardown-me")
	}
}

func TestLoad_RejectsMultipleDocuments(t *testing.T) {
	_, _, err := Load(writeBox(t, "version: 1\nname: first\n---\nversion: 1\nname: second\n"))
	if err == nil {
		t.Fatal("Load() error = nil, want single-document error")
	}
	if !strings.Contains(err.Error(), "single YAML document") {
		t.Errorf("Load() error = %q, want the single-document error", err)
	}
}

func TestLoad_NonIntVersion(t *testing.T) {
	_, _, err := Load(writeBox(t, "version: \"1\"\nname: t\n"))
	if err == nil {
		t.Fatal("Load() error = nil, want version type error")
	}
	if !strings.Contains(err.Error(), "must be an integer") {
		t.Errorf("Load() error = %q, want an explicit integer-version error", err)
	}
}

func TestLoad_EmptyAndCommentsOnly(t *testing.T) {
	for _, content := range []string{"", "# just a comment\n", "---\n"} {
		_, _, err := Load(writeBox(t, content))
		if err == nil {
			t.Fatalf("Load(%q) error = nil, want missing-version error", content)
		}
		if !strings.Contains(err.Error(), "version") {
			t.Errorf("Load(%q) error = %q, want the missing-version error", content, err)
		}
	}
}

// TestLoad_ExamplesParseStrictly keeps the shipped examples parseable under the
// strict loader.
func TestLoad_ExamplesParseStrictly(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "examples", "*", "abox.yaml"))
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no examples/*/abox.yaml matched; fix the glob rather than letting this pass vacuously")
	}
	for _, path := range matches {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			if _, _, err := LoadFile(path); err != nil {
				t.Errorf("LoadFile(%s) error = %v", path, err)
			}
		})
	}
}

func TestClosest(t *testing.T) {
	candidates := []string{"version", "name", "cpus", "memory", "disk", "allowlist"}
	tests := []struct {
		in   string
		want string
	}{
		{"memroy", "memory"},
		{"cpu", "cpus"},
		{"alowlist", "allowlist"},
		{"completely_unrelated_key", ""},
		{"xyz", ""},
	}
	for _, tt := range tests {
		if got := closest(tt.in, candidates); got != tt.want {
			t.Errorf("closest(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestLoad_UnknownKeyWithSpace guards the unknown-key regex against keys that
// contain whitespace. "max connections" is a plausible typo for
// max_connections, and a \S+ key pattern silently failed to match it, falling
// through to the verbatim branch and printing the Go type name at the user.
func TestLoad_UnknownKeyWithSpace(t *testing.T) {
	_, _, err := Load(writeBox(t, "version: 1\nname: t\nhttp:\n  max connections: 5\n"))
	if err == nil {
		t.Fatal("Load() error = nil, want unknown-key error")
	}
	if !strings.Contains(err.Error(), `unknown key "http.max connections"`) {
		t.Errorf("Load() error = %q, want the spaced key reported as a dotted abox.yaml key", err)
	}
	for _, leak := range []string{"boxfile.", "BoxfileHTTP"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("Load() error = %q, leaks Go type name %q", err, leak)
		}
	}
	if hint := hintFromErr(err); !strings.Contains(hint, `did you mean "http.max_connections"?`) {
		t.Errorf("hint = %q, want the underscore spelling suggested", hint)
	}
}

// TestLoad_AcceptsTrailingDocumentSeparator checks the single-document rule does
// not fire on a trailing "---", which parses as an empty document and hides
// nothing. It would otherwise also break `abox down` on a harmless file.
func TestLoad_AcceptsTrailingDocumentSeparator(t *testing.T) {
	for _, content := range []string{
		"version: 1\nname: t\n---\n",
		"version: 1\nname: t\n---\n# trailing comment\n",
		"version: 1\nname: t\n...\n",
	} {
		box, _, err := Load(writeBox(t, content))
		if err != nil {
			t.Errorf("Load(%q) error = %v, want success (no content is being dropped)", content, err)
			continue
		}
		if box.Name != "t" {
			t.Errorf("Load(%q).Name = %q, want %q", content, box.Name, "t")
		}
	}
}

// TestLoadLenient_ToleratesVersionProblems pins the teardown contract: nothing
// in the file may stand between the user and the instance name. Leniency that
// covered only unknown keys would still block `abox down` on a future version
// or a stray document.
func TestLoadLenient_ToleratesVersionProblems(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"future version", "version: 99\nname: teardown-me\n"},
		{"missing version", "name: teardown-me\n"},
		{"non-int version", "version: \"1\"\nname: teardown-me\n"},
		{"multiple documents", "version: 1\nname: teardown-me\n---\nname: other\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeBox(t, tt.content)
			if _, _, err := Load(dir); err == nil {
				t.Error("Load() error = nil; the strict loader should reject this")
			}
			box, _, err := LoadLenient(dir)
			if err != nil {
				t.Fatalf("LoadLenient() error = %v; teardown must still read the name", err)
			}
			if box.Name != "teardown-me" {
				t.Errorf("LoadLenient().Name = %q, want %q", box.Name, "teardown-me")
			}
		})
	}
}

// TestBoxfileTypes_CoversEveryNestedStruct keeps the Go-type -> key-path table in
// step with the struct. A nested struct missing from it still gets its typos
// caught, but they are reported as a bare key with no path and no suggestion,
// which is indistinguishable from a top-level key.
func TestBoxfileTypes_CoversEveryNestedStruct(t *testing.T) {
	var walk func(t reflect.Type)
	seen := map[reflect.Type]bool{}
	walk = func(rt reflect.Type) {
		if seen[rt] {
			return
		}
		seen[rt] = true
		if _, ok := boxfileTypes[rt.String()]; !ok {
			t.Errorf("boxfileTypes has no entry for %s; add its abox.yaml key path so "+
				"unknown keys inside it are reported with a dotted path and a suggestion", rt)
		}
		for f := range rt.Fields() {
			if f.PkgPath != "" {
				continue
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft)
			}
		}
	}
	walk(reflect.TypeFor[Boxfile]())
}

// TestValidate_NamesTheFileItWasLoadedFrom checks validation errors name the
// file the user actually passed. create --from-file accepts any filename, so a
// hardcoded "abox.yaml" would point at a file they never mentioned.
func TestValidate_NamesTheFileItWasLoadedFrom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("write custom.yaml: %v", err)
	}

	box, boxDir, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	err = box.Validate(boxDir)
	if err == nil {
		t.Fatal("Validate() error = nil, want the missing-name error")
	}
	if !strings.Contains(err.Error(), "custom.yaml") {
		t.Errorf("Validate() error = %q, want it to name custom.yaml", err)
	}

	// A Boxfile built in memory still says abox.yaml.
	if err := (&Boxfile{Version: 1}).Validate(dir); err == nil ||
		!strings.Contains(err.Error(), "abox.yaml") {
		t.Errorf("in-memory Validate() error = %v, want it to default to abox.yaml", err)
	}
}
