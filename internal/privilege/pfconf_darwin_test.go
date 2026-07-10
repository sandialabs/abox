//go:build darwin

package privilege

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const defaultApplePfconf = `#
# Default PF configuration file.
#
# This file contains the main ruleset, which gets automatically loaded
# at startup.  PF will not be automatically enabled, however.  Instead,
# each component which utilizes PF is responsible for enabling and
# disabling PF via -E and -X as documented in pfctl(8).
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

// writePfconf creates a temp pf.conf with the given content and returns its path.
func writePfconf(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed pf.conf: %v", err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// indexOfLine returns the position of the first line in content whose trimmed
// form equals target. Returns -1 if not found. Helper for ordering checks.
func indexOfLine(content, target string) int {
	want := strings.TrimSpace(target)
	for i, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == want {
			return i
		}
	}
	return -1
}

// countLines returns the number of lines in content whose trimmed form equals
// target. Use instead of strings.Count when target may be a substring of
// other lines (e.g. `anchor "abox/*"` is a suffix of `rdr-anchor "abox/*"`).
func countLines(content, target string) int {
	want := strings.TrimSpace(target)
	n := 0
	for line := range strings.SplitSeq(content, "\n") {
		if strings.TrimSpace(line) == want {
			n++
		}
	}
	return n
}

func TestEnsureAnchorReferences_DefaultApple(t *testing.T) {
	path := writePfconf(t, defaultApplePfconf)

	changed, err := ensureAnchorReferences(path)
	if err != nil {
		t.Fatalf("ensureAnchorReferences: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on default Apple pf.conf")
	}

	got := readFile(t, path)

	// Both lines must be present.
	if !containsLine(got, pfconfRdrAnchorLine) {
		t.Errorf("missing rdr-anchor in:\n%s", got)
	}
	if !containsLine(got, pfconfFilterAnchorLine) {
		t.Errorf("missing anchor in:\n%s", got)
	}

	// Section ordering: rdr-anchor "abox/*" must precede anchor "com.apple/*"
	// (which is the start of the filter section).
	rdrIdx := indexOfLine(got, pfconfRdrAnchorLine)
	filterMarkerIdx := indexOfLine(got, pfconfFilterAnchorMarker)
	if rdrIdx >= filterMarkerIdx {
		t.Errorf("rdr-anchor must precede filter anchor (rdr=%d, filter=%d):\n%s",
			rdrIdx, filterMarkerIdx, got)
	}

	// abox lines should be immediately after their com.apple/* siblings.
	rdrMarkerIdx := indexOfLine(got, pfconfRdrAnchorMarker)
	if rdrIdx != rdrMarkerIdx+1 {
		t.Errorf("rdr-anchor abox should be on line after rdr-anchor com.apple "+
			"(marker=%d, abox=%d):\n%s", rdrMarkerIdx, rdrIdx, got)
	}
	filterIdx := indexOfLine(got, pfconfFilterAnchorLine)
	if filterIdx != filterMarkerIdx+1 {
		t.Errorf("anchor abox should be on line after anchor com.apple "+
			"(marker=%d, abox=%d):\n%s", filterMarkerIdx, filterIdx, got)
	}

	// Apple defaults preserved.
	if !strings.Contains(got, `anchor "com.apple/*"`) ||
		!strings.Contains(got, `rdr-anchor "com.apple/*"`) {
		t.Errorf("apple anchors lost:\n%s", got)
	}
}

func TestEnsureAnchorReferences_WrittenFileIsValidOrder(t *testing.T) {
	// Regression test for the bug where appending at end-of-file landed
	// rdr-anchor in the filter section. The `load anchor` line is the last
	// line in default pf.conf and is in the filter section; our rdr-anchor
	// must NOT appear after it.
	path := writePfconf(t, defaultApplePfconf)

	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("ensureAnchorReferences: %v", err)
	}

	got := readFile(t, path)
	rdrAboxIdx := indexOfLine(got, pfconfRdrAnchorLine)
	loadAnchorIdx := -1
	for i, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "load anchor") {
			loadAnchorIdx = i
			break
		}
	}
	if loadAnchorIdx >= 0 && rdrAboxIdx > loadAnchorIdx {
		t.Errorf("rdr-anchor must come before load anchor / filter section "+
			"(rdr=%d, load=%d):\n%s", rdrAboxIdx, loadAnchorIdx, got)
	}
}

func TestEnsureAnchorReferences_AlreadyWired(t *testing.T) {
	path := writePfconf(t, defaultApplePfconf)
	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	before := readFile(t, path)

	changed, err := ensureAnchorReferences(path)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if changed {
		t.Error("expected changed=false on already-wired file")
	}
	if got := readFile(t, path); got != before {
		t.Errorf("file modified on no-op call:\nbefore:\n%s\nafter:\n%s", before, got)
	}
}

func TestEnsureAnchorReferences_PartialState_OnlyRdrPresent(t *testing.T) {
	// User (or a previous run) wrote only the rdr line. We add only the missing
	// filter line; rdr is left untouched (no duplicate).
	// Newline-anchored replace ensures we only match the actual rdr-anchor
	// line, not embedded substrings.
	partial := strings.Replace(defaultApplePfconf,
		"\n"+pfconfRdrAnchorMarker+"\n",
		"\n"+pfconfRdrAnchorMarker+"\n"+pfconfRdrAnchorLine+"\n", 1)
	path := writePfconf(t, partial)

	changed, err := ensureAnchorReferences(path)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true (filter line missing)")
	}

	got := readFile(t, path)
	if n := countLines(got, pfconfRdrAnchorLine); n != 1 {
		t.Errorf("rdr line should appear exactly once, got %d:\n%s", n, got)
	}
	if !containsLine(got, pfconfFilterAnchorLine) {
		t.Errorf("filter line should now be present:\n%s", got)
	}
}

func TestEnsureAnchorReferences_PartialState_OnlyFilterPresent(t *testing.T) {
	// `anchor "com.apple/*"` is a substring of `scrub-anchor "com.apple/*"` and
	// other *-anchor lines, so anchor on the surrounding newlines.
	partial := strings.Replace(defaultApplePfconf,
		"\n"+pfconfFilterAnchorMarker+"\n",
		"\n"+pfconfFilterAnchorMarker+"\n"+pfconfFilterAnchorLine+"\n", 1)
	path := writePfconf(t, partial)

	changed, err := ensureAnchorReferences(path)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true (rdr line missing)")
	}

	got := readFile(t, path)
	if n := countLines(got, pfconfFilterAnchorLine); n != 1 {
		t.Errorf("filter line should appear exactly once, got %d:\n%s", n, got)
	}
	if !containsLine(got, pfconfRdrAnchorLine) {
		t.Errorf("rdr line should now be present:\n%s", got)
	}
}

func TestEnsureAnchorReferences_MissingMarkers(t *testing.T) {
	// Custom pf.conf without Apple's anchors — we refuse to guess.
	custom := `#
# Custom pf.conf with no Apple anchors.
#
pass in all
`
	path := writePfconf(t, custom)

	changed, err := ensureAnchorReferences(path)
	if err == nil {
		t.Fatal("expected error when Apple markers missing")
	}
	if changed {
		t.Error("must not modify file when markers missing")
	}
	// Error must mention what to do.
	msg := err.Error()
	for _, want := range []string{
		`rdr-anchor "abox/*"`,
		`anchor "abox/*"`,
		"manually",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q:\n%s", want, msg)
		}
	}

	// File must be byte-identical.
	if got := readFile(t, path); got != custom {
		t.Errorf("file modified despite error:\n%s", got)
	}
}

func TestEnsureAnchorReferences_OnlyOneMarkerMissing(t *testing.T) {
	// Drop the filter marker only — should still error (we need both).
	noFilter := strings.Replace(defaultApplePfconf,
		"\nanchor \"com.apple/*\"\n", "\n", 1)
	path := writePfconf(t, noFilter)

	if _, err := ensureAnchorReferences(path); err == nil {
		t.Fatal("expected error when filter marker missing")
	}
}

func TestEnsureAnchorReferences_PreservesMode(t *testing.T) {
	path := writePfconf(t, defaultApplePfconf)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("ensureAnchorReferences: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestEnsureAnchorReferences_MissingFile(t *testing.T) {
	_, err := ensureAnchorReferences(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRemoveAnchorReferences_RoundTrip(t *testing.T) {
	path := writePfconf(t, defaultApplePfconf)

	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	changed, err := removeAnchorReferences(path)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !changed {
		t.Error("expected changed=true on remove")
	}

	got := readFile(t, path)
	if containsLine(got, pfconfRdrAnchorLine) {
		t.Errorf("rdr-anchor still present:\n%s", got)
	}
	if containsLine(got, pfconfFilterAnchorLine) {
		t.Errorf("anchor still present:\n%s", got)
	}
	if !strings.Contains(got, `anchor "com.apple/*"`) {
		t.Errorf("apple filter anchor lost:\n%s", got)
	}
	if !strings.Contains(got, `rdr-anchor "com.apple/*"`) {
		t.Errorf("apple rdr anchor lost:\n%s", got)
	}
}

func TestRemoveAnchorReferences_NotPresent(t *testing.T) {
	path := writePfconf(t, defaultApplePfconf)

	changed, err := removeAnchorReferences(path)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if changed {
		t.Error("expected changed=false when nothing to remove")
	}
	if got := readFile(t, path); got != defaultApplePfconf {
		t.Errorf("file modified on no-op remove:\n%s", got)
	}
}

func TestEnsureRemoveCycle_StableContent(t *testing.T) {
	path := writePfconf(t, defaultApplePfconf)

	for i := range 3 {
		if _, err := ensureAnchorReferences(path); err != nil {
			t.Fatalf("cycle %d ensure: %v", i, err)
		}
		if _, err := removeAnchorReferences(path); err != nil {
			t.Fatalf("cycle %d remove: %v", i, err)
		}
	}

	got := readFile(t, path)
	if strings.TrimRight(got, "\n") != strings.TrimRight(defaultApplePfconf, "\n") {
		t.Errorf("content drifted across cycles:\nwant:\n%s\ngot:\n%s",
			defaultApplePfconf, got)
	}
}

func TestHasAnchorReferences_PublicAPI(t *testing.T) {
	path := writePfconf(t, defaultApplePfconf)

	present, err := HasAnchorReferences(path)
	if err != nil {
		t.Fatalf("HasAnchorReferences: %v", err)
	}
	if present {
		t.Error("default pf.conf should not have abox references")
	}

	if _, err := ensureAnchorReferences(path); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	present, err = HasAnchorReferences(path)
	if err != nil {
		t.Fatalf("HasAnchorReferences after wire: %v", err)
	}
	if !present {
		t.Error("expected references after wire")
	}
}

func TestCanAutoWireAnchors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"default Apple has both markers", defaultApplePfconf, true},
		{
			"missing rdr marker",
			strings.Replace(defaultApplePfconf, "\n"+pfconfRdrAnchorMarker+"\n", "\n", 1),
			false,
		},
		{
			"missing filter marker",
			strings.Replace(defaultApplePfconf, "\n"+pfconfFilterAnchorMarker+"\n", "\n", 1),
			false,
		},
		{"empty file", "", false},
		{
			"markers commented out",
			"# " + pfconfRdrAnchorMarker + "\n# " + pfconfFilterAnchorMarker + "\n",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePfconf(t, tt.content)
			got, err := CanAutoWireAnchors(path)
			if err != nil {
				t.Fatalf("CanAutoWireAnchors: %v", err)
			}
			if got != tt.want {
				t.Errorf("CanAutoWireAnchors = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCanAutoWireAnchors_MissingFile(t *testing.T) {
	_, err := CanAutoWireAnchors(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHasAnchorReferences_BothMustBePresent(t *testing.T) {
	// Only one line present → should report false.
	partial := defaultApplePfconf + pfconfRdrAnchorLine + "\n"
	path := writePfconf(t, partial)

	present, err := HasAnchorReferences(path)
	if err != nil {
		t.Fatalf("HasAnchorReferences: %v", err)
	}
	if present {
		t.Error("HasAnchorReferences should require BOTH lines")
	}
}

func TestContainsLine_IgnoresComments(t *testing.T) {
	commented := defaultApplePfconf + "\n" + `# rdr-anchor "abox/*"` + "\n"
	if containsLine(commented, pfconfRdrAnchorLine) {
		t.Error("commented line should not count as present")
	}
}

func TestRemoveLines_PreservesComments(t *testing.T) {
	// Comments matching the line should NOT be removed.
	content := pfconfRdrAnchorLine + "\n" + `# ` + pfconfRdrAnchorLine + "\n"
	got, removed := removeLines(content, pfconfRdrAnchorLine)
	if !removed {
		t.Fatal("expected removed=true")
	}
	if !strings.Contains(got, `# `+pfconfRdrAnchorLine) {
		t.Errorf("comment should be preserved:\n%s", got)
	}
	if strings.Contains(strings.TrimSpace(strings.Split(got, "\n")[0]), pfconfRdrAnchorLine) {
		// First line should now be the comment, not the bare directive.
		if !strings.HasPrefix(strings.TrimSpace(strings.Split(got, "\n")[0]), "#") {
			t.Errorf("non-comment line not removed:\n%s", got)
		}
	}
}

func TestInsertAfterLine_PreservesIndentation(t *testing.T) {
	content := "    " + pfconfRdrAnchorMarker + "\n"
	got := insertAfterLine(content, pfconfRdrAnchorMarker, pfconfRdrAnchorLine)
	wantLine := "    " + pfconfRdrAnchorLine
	if !strings.Contains(got, wantLine) {
		t.Errorf("indentation not preserved; got:\n%s", got)
	}
}

func TestInsertAfterLine_MarkerOnLastLineNoNewline(t *testing.T) {
	content := "header\n" + pfconfRdrAnchorMarker
	got := insertAfterLine(content, pfconfRdrAnchorMarker, pfconfRdrAnchorLine)
	if !strings.Contains(got, pfconfRdrAnchorMarker+"\n"+pfconfRdrAnchorLine) {
		t.Errorf("insertion after EOF marker lost separator; got:\n%q", got)
	}
}

func TestAtomicWrite_NoTempLeftover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(path, []byte("orig"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := atomicWrite(path, []byte("new"), 0o644); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "abox-tmp") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}
